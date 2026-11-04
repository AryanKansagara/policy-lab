import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { capsAllow, capsBetween, capWeight, computeMatrix, Ctx, diffPolicies, explain, formatCaps, inferInventory, inventoryFromStatus, isTagged, lint, loadPolicy, resolveSrc, resolveTargets, ROLES, runTests, sanitizeInventory, sshEval, targetLabel, type Cap, type Device, type Inventory, type Policy, type Problem, type Role, type Severity, type Target, type TestResult } from './engine.ts'
import { Editor, type Mark, type Tone } from './Editor.tsx'
import { LiveGraph } from './LiveGraph.tsx'
import { buildGraph, type GNode } from './graph.ts'
import { SAMPLES, type Sample } from './samples.ts'
import { decodeState, encodeState } from './share.ts'
import { Brand, Footer, ThemeToggle } from './ui.tsx'

const STORE = 'policy-lab:v1'
type TabId = 'matrix' | 'why' | 'tests' | 'diff' | 'lints' | 'graph' | 'inventory'
const TABS: { id: TabId; label: string }[] = [
  { id: 'matrix', label: 'Access matrix' },
  { id: 'why', label: 'Why?' },
  { id: 'tests', label: 'Tests' },
  { id: 'diff', label: 'Policy diff' },
  { id: 'lints', label: 'Lints' },
  { id: 'graph', label: 'Graph' },
  { id: 'inventory', label: 'Inventory' },
]
interface Trace { src: string; dst: string; proto: string; port: string; sshUser: string }
const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v))
const defaultTrace = (inv: Inventory): Trace => ({
  src: inv.devices.find((d) => !isTagged(d))?.name ?? inv.users[0]?.email ?? '',
  dst: inv.devices.find(isTagged)?.name ?? inv.devices[0]?.name ?? '',
  proto: 'tcp', port: '443', sshUser: 'ubuntu',
})

function initialState(): { text: string; inv: Inventory; old: string; sampleId: string } {
  const param = new URLSearchParams(location.search).get('sample')
  const fromParam = SAMPLES.find((s) => s.id === param)
  if (fromParam) return { text: fromParam.policy, inv: clone(fromParam.inventory), old: fromParam.previous, sampleId: fromParam.id }
  try {
    const raw = JSON.parse(localStorage.getItem(STORE) ?? 'null')
    if (raw && typeof raw.text === 'string') return { text: raw.text, inv: sanitizeInventory(raw.inv), old: String(raw.old ?? ''), sampleId: String(raw.sampleId ?? '') }
  } catch { /* corrupt storage falls through to the default sample */ }
  const s = SAMPLES[0]
  return { text: s.policy, inv: clone(s.inventory), old: s.previous, sampleId: s.id }
}

export default function Tool() {
  const [init] = useState(initialState)
  const [text, setText] = useState(init.text)
  const [inv, setInv] = useState(init.inv)
  const [old, setOld] = useState(init.old)
  const [sampleId, setSampleId] = useState(init.sampleId)
  const [tab, setTab] = useState<TabId>('matrix')
  const [trace, setTrace] = useState<Trace>(() => defaultTrace(init.inv))
  const [reveal, setReveal] = useState<{ paths: string[]; tone: Tone; nonce: number } | null>(null)
  const [toast, setToast] = useState('')
  const deferred = useDeferredValue(text)
  const loaded = useMemo(() => loadPolicy(deferred), [deferred])
  const lastGood = useRef<Policy | null>(null)
  if (loaded.policy) lastGood.current = loaded.policy
  const policy = loaded.policy ?? lastGood.current
  const fileInput = useRef<HTMLInputElement>(null)

  const say = useCallback((m: string) => {
    setToast(m)
    window.setTimeout(() => setToast((t) => (t === m ? '' : t)), 3200)
  }, [])

  // Shared URL wins over everything, then gets folded into local state.
  useEffect(() => {
    const m = /^#s=(.+)$/.exec(location.hash)
    const url = new URL(location.href)
    if (url.searchParams.has('sample')) {
      url.searchParams.delete('sample')
      history.replaceState({}, '', url.pathname + url.search + url.hash)
    }
    if (!m) return
    decodeState(m[1])
      .then((v) => {
        const s = v as { t?: unknown; i?: unknown; o?: unknown }
        if (typeof s.t !== 'string') throw new Error('bad state')
        const i = sanitizeInventory(s.i)
        setText(s.t)
        setInv(i)
        setOld(typeof s.o === 'string' ? s.o : '')
        setSampleId('')
        setTrace(defaultTrace(i))
        say('Loaded shared policy')
      })
      .catch(() => say('That share link is damaged, so it was ignored'))
      .finally(() => history.replaceState({}, '', location.pathname + location.search))
  }, [say])

  useEffect(() => {
    const id = window.setTimeout(() => {
      try { localStorage.setItem(STORE, JSON.stringify({ text, inv, old, sampleId })) } catch { /* storage full: the session still works */ }
    }, 300)
    return () => window.clearTimeout(id)
  }, [text, inv, old, sampleId])

  const loadSample = (s: Sample) => {
    setText(s.policy)
    const i = clone(s.inventory)
    setInv(i)
    setOld(s.previous)
    setSampleId(s.id)
    setTrace(defaultTrace(i))
    setReveal(null)
  }
  const share = async () => {
    const code = await encodeState({ t: text, i: inv, o: old })
    const url = `${location.origin}/app#s=${code}`
    try {
      await navigator.clipboard.writeText(url)
      say('Share link copied. The policy lives in the link, not on a server.')
    } catch {
      history.replaceState({}, '', `/app#s=${code}`)
      say('Copy was blocked, so the link is in your address bar')
    }
  }
  const upload = async (f: File | undefined) => {
    if (!f) return
    const t = await f.text()
    setText(t)
    setSampleId('')
    const l = loadPolicy(t)
    if (l.policy) {
      const i = inferInventory(l.policy)
      setInv(i)
      setTrace(defaultTrace(i))
      say(`Loaded ${f.name} and inferred an inventory from it`)
    } else say(`Loaded ${f.name}, which has a syntax error`)
  }
  const useInferred = () => {
    if (!policy) return
    const i = inferInventory(policy)
    setInv(i)
    setTrace(defaultTrace(i))
    say(`Inferred ${i.users.length} users and ${i.devices.length} devices from the policy`)
  }

  const results = useMemo(() => (policy ? runTests(policy, inv) : []), [policy, inv])
  const lints = useMemo(() => (policy ? lint(policy, inv) : []), [policy, inv])
  const failing = results.filter((r) => !r.ok).length
  const lintBad = lints.filter((l) => l.severity !== 'info').length

  // True when the inventory has nothing to do with the policy (typical after pasting your own).
  const mismatch = useMemo(() => {
    if (!policy) return false
    const tags = Object.keys(policy.tagOwners)
    const members = Object.values(policy.groups).flat().map((m) => m.toLowerCase())
    if (!tags.length && !members.length) return false
    return !inv.devices.some((d) => d.tags.some((t) => tags.includes(t))) && !inv.users.some((u) => members.includes(u.email.toLowerCase()))
  }, [policy, inv])

  // Trace is computed here because its result also drives the editor highlights.
  const traced = useMemo(() => (policy ? runTrace(policy, inv, trace) : null), [policy, inv, trace])

  const pathSpan = useCallback((p: string) => loaded.parse.spans.get(p) ?? loaded.parse.keySpans.get(p), [loaded])
  const marks = useMemo(() => {
    const out: Mark[] = []
    const add = (path: string, tone: Tone, inline?: boolean) => {
      const s = pathSpan(path)
      if (s) out.push({ ...s, tone, inline })
    }
    if (tab === 'why' && traced && !('error' in traced)) {
      for (const n of traced.exp.near) add(n.rule.path, 'near')
      for (const h of traced.exp.hits) {
        add(h.rule.path, 'hit')
        add(h.srcSel.path, 'hit', true)
        add(h.dst.path, 'hit', true)
      }
      if (traced.ssh?.rule) add(traced.ssh.rule.path, traced.ssh.action === 'deny' ? 'near' : 'hit')
    }
    if (reveal) for (const p of reveal.paths) add(p, reveal.tone)
    const e = loaded.parse.error
    if (e) {
      const end = Math.min(deferred.length, e.offset + 1)
      out.push({ start: e.offset, end: Math.max(end, e.offset + 1), tone: 'err' }, { start: e.offset, end: Math.max(end, e.offset + 1), tone: 'err', inline: true })
    }
    return out
  }, [tab, traced, reveal, loaded, pathSpan, deferred])

  const firstHit = tab === 'why' && traced && !('error' in traced) ? traced.exp.hits[0]?.rule.path ?? traced.ssh?.rule?.path : undefined
  const revealPath = reveal?.paths[0] ?? firstHit
  const revealOffset = loaded.parse.error?.offset ?? (revealPath ? pathSpan(revealPath)?.start : undefined)
  const revealKey = `${reveal?.nonce ?? 0}|${revealPath ?? ''}|${loaded.parse.error?.offset ?? ''}`
  const showPath = (paths: string[], tone: Tone = 'info') => setReveal({ paths, tone, nonce: Date.now() })
  const traceTo = (t: Partial<Trace>) => {
    setTrace((c) => ({ ...c, ...t }))
    setReveal(null)
    setTab('why')
  }

  useEffect(() => setReveal(null), [tab])

  const tabRefs = useRef<Partial<Record<TabId, HTMLButtonElement | null>>>({})
  const tabKeys = (e: KeyboardEvent) => {
    const i = TABS.findIndex((t) => t.id === tab)
    const n = e.key === 'ArrowRight' ? (i + 1) % TABS.length : e.key === 'ArrowLeft' ? (i - 1 + TABS.length) % TABS.length : -1
    if (n < 0) return
    e.preventDefault()
    setTab(TABS[n].id)
    tabRefs.current[TABS[n].id]?.focus()
  }
  const err = loaded.parse.error

  return (
    <div className="tool">
      <header className="topbar">
        <Brand />
        <nav className="topbar-actions" aria-label="Workspace">
          <label className="field-inline">
            <span className="mono-label">Sample</span>
            <select value={sampleId} onChange={(e) => { const s = SAMPLES.find((x) => x.id === e.target.value); if (s) loadSample(s) }}>
              {!sampleId && <option value="">Your policy</option>}
              {SAMPLES.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
          </label>
          <input ref={fileInput} type="file" accept=".json,.hujson,.txt,application/json" hidden onChange={(e) => { void upload(e.target.files?.[0]); e.target.value = '' }} />
          <button type="button" className="btn" onClick={() => fileInput.current?.click()}>Upload</button>
          <button type="button" className="btn primary" onClick={() => void share()}><span className="wide-only">Copy share link</span><span className="narrow-only">Share</span></button>
          <ThemeToggle />
        </nav>
      </header>

      <main className="workspace">
        <section className="pane pane-editor" aria-label="Policy editor">
          <div className="pane-head">
            <span className="mono-label">policy.hujson</span>
            {err
              ? <span className="status bad" role="status">✕ Line {err.line}, col {err.col}</span>
              : <span className="status ok" role="status">✓ Valid HuJSON</span>}
          </div>
          <Editor value={text} onChange={(v) => { setText(v); setSampleId(''); setReveal(null) }} marks={marks} revealOffset={revealOffset} revealNonce={revealKey} label="Tailnet policy file" />
          {err && (
            <div className="ed-error" role="alert">
              <strong>{err.message}</strong>
              <span>Results below use the last version that parsed.</span>
            </div>
          )}
          <p className="pane-foot">Paste your own policy here. Nothing leaves your browser. Press Esc, then Tab, to leave the editor.</p>
        </section>

        <section className="pane pane-views">
          <div className="tabs" role="tablist" aria-label="Views" onKeyDown={tabKeys}>
            {TABS.map((t) => {
              const n = t.id === 'tests' ? failing : t.id === 'lints' ? lintBad : 0
              return (
                <button key={t.id} ref={(el) => { tabRefs.current[t.id] = el }} type="button" role="tab" id={`tab-${t.id}`} aria-selected={tab === t.id} aria-controls="view" tabIndex={tab === t.id ? 0 : -1} className="tab" onClick={() => setTab(t.id)}>
                  {t.label}
                  {n > 0 && <span className={`badge ${t.id === 'tests' ? 'badge-bad' : 'badge-warn'}`} aria-label={`${n} issues`}>{n}</span>}
                </button>
              )
            })}
          </div>
          {mismatch && (
            <div className="banner">
              <span>This policy doesn't mention anyone in the current inventory, so most access will look empty.</span>
              <button type="button" className="btn" onClick={useInferred}>Infer inventory from policy</button>
            </div>
          )}
          <div id="view" role="tabpanel" aria-labelledby={`tab-${tab}`} className="view" key={tab}>
            {!policy ? <Empty title="Fix the syntax error to see results" body="Policy Lab needs one version of the policy that parses." />
              : tab === 'matrix' ? <MatrixView policy={policy} inv={inv} onTrace={traceTo} onInfer={useInferred} />
              : tab === 'why' ? <WhyView inv={inv} trace={trace} setTrace={setTrace} traced={traced} showPath={showPath} />
              : tab === 'tests' ? <TestsView results={results} showPath={showPath} onTrace={traceTo} />
              : tab === 'diff' ? <DiffView policy={policy} inv={inv} old={old} setOld={setOld} text={text} sample={SAMPLES.find((s) => s.id === sampleId)} onTrace={traceTo} />
              : tab === 'lints' ? <LintsView lints={lints} showPath={showPath} />
              : tab === 'graph' ? <GraphView policy={policy} inv={inv} onInfer={useInferred} />
              : <InventoryView inv={inv} setInv={setInv} onInfer={useInferred} say={say} />}
          </div>
        </section>
      </main>
      <Footer />
      <div className={`toast${toast ? ' show' : ''}`} role="status">{toast}</div>
    </div>
  )
}

function Empty({ title, body, action }: { title: string; body: string; action?: ReactNode }) {
  return (
    <div className="empty">
      <h3>{title}</h3>
      <p>{body}</p>
      {action}
    </div>
  )
}
function Tile({ label, value, note }: { label: string; value: ReactNode; note?: string }) {
  return (
    <div className="tile">
      <span className="mono-label">{label}</span>
      <strong>{value}</strong>
      {note && <small>{note}</small>}
    </div>
  )
}
const pretty = (path: string) => path.replace(/\.(\d+)/g, '[$1]')

// ---------- matrix ----------
function shortCaps(caps: Cap[]) {
  const f = formatCaps(caps)
  if (f === 'all') return 'all'
  const single = /^[a-z+-]+:(\d+|\*)$/.exec(f)
  if (single) return single[1]
  const n = new Set(caps.map((c) => `${c.lo}-${c.hi}`)).size
  return n > 9 ? '9+' : `${n}p` // n distinct port specs; the inspector shows them all
}
function MatrixView({ policy, inv, onTrace, onInfer }: { policy: Policy; inv: Inventory; onTrace: (t: Partial<Trace>) => void; onInfer: () => void }) {
  const [portText, setPortText] = useState('')
  const [hover, setHover] = useState<{ s: Device; t: Target; caps: Cap[] } | null>(null)
  const m = useMemo(() => computeMatrix(policy, inv), [policy, inv])
  const ctx = useMemo(() => new Ctx(policy, inv), [policy, inv])
  const port = /^\d+$/.test(portText) ? Number(portText) : null
  const visible = (c: Cap[]) => c.length > 0 && (port === null || capsAllow(c, 'tcp', port) || capsAllow(c, 'udp', port))
  const stats = useMemo(() => {
    let on = 0
    let total = 0
    const inbound = m.targets.map(() => 0)
    const outbound = m.sources.map(() => 0)
    m.cells.forEach((row, i) => row.forEach((c, j) => {
      const t = m.targets[j]
      if (t.kind === 'device' && t.dev === m.sources[i]) return
      total++
      if (visible(c)) { on++; inbound[j]++; outbound[i]++ }
    }))
    const mi = inbound.indexOf(Math.max(...inbound, 0))
    const mo = outbound.indexOf(Math.max(...outbound, 0))
    return { on, total, target: m.targets[mi], tn: inbound[mi] ?? 0, source: m.sources[mo], sn: outbound[mo] ?? 0 }
  }, [m, port])
  if (!inv.devices.length) return <Empty title="No devices to evaluate" body="The matrix needs an inventory. Infer one from your policy, or add devices on the Inventory tab." action={<button type="button" className="btn primary" onClick={onInfer}>Infer inventory from policy</button>} />
  const hoverRules = hover ? [...new Set(capsBetween(ctx, hover.s, hover.t).hits.map((h) => pretty(h.rule.path)))] : []
  const pct = stats.total ? Math.round((stats.on / stats.total) * 100) : 0
  return (
    <>
      <div className="tiles">
        <Tile label="Allowed paths" value={stats.on} note={`of ${stats.total} possible`} />
        <Tile label="Mesh coverage" value={`${pct}%`} note={port === null ? 'any port' : `on port ${port}`} />
        <Tile label="Most exposed" value={stats.tn && stats.target ? targetLabel(stats.target) : 'none'} note={stats.tn ? `reachable from ${stats.tn} ${stats.tn === 1 ? 'device' : 'devices'}` : undefined} />
        <Tile label="Widest source" value={stats.sn && stats.source ? stats.source.name : 'none'} note={stats.sn ? `reaches ${stats.sn} ${stats.sn === 1 ? 'destination' : 'destinations'}` : undefined} />
      </div>
      <div className="toolbar">
        <label className="field-inline">
          <span className="mono-label">Filter by port</span>
          <input className="small-input" inputMode="numeric" placeholder="any" value={portText} onChange={(e) => setPortText(e.target.value.trim())} />
        </label>
        <div className="legend" aria-label="Legend: cell color shows how many ports are open">
          <span>Ports open</span>
          <i className="swatch" style={{ '--w': 34 } as React.CSSProperties} /><span>one</span>
          <i className="swatch" style={{ '--w': 62 } as React.CSSProperties} /><span>range</span>
          <i className="swatch" style={{ '--w': 100 } as React.CSSProperties} /><span>all</span>
        </div>
      </div>
      <div className="inspector" aria-live="polite">
        {hover
          ? <><strong>{hover.s.name}</strong> → <strong>{targetLabel(hover.t)}</strong>: <code>{formatCaps(hover.caps) || 'denied'}</code>{hoverRules.length > 0 && <span className="muted"> from {hoverRules.join(', ')}</span>}</>
          : <span className="muted">Hover or focus a cell for details. Select it to trace the decision.</span>}
      </div>
      <div className="matrix-scroll">
        <table className="matrix">
          <caption className="sr-only">Access from each source device (rows) to each destination (columns)</caption>
          <thead>
            <tr>
              <th className="corner"><span className="mono-label">From ↓ / To →</span></th>
              {m.targets.map((t) => <th key={targetLabel(t)} scope="col" className="col"><span>{targetLabel(t)}</span></th>)}
            </tr>
          </thead>
          <tbody>
            {m.sources.map((s, i) => (
              <tr key={s.name + i}>
                <th scope="row" className="rowh">
                  <span>{s.name}</span>
                  <small>{s.tags.length ? s.tags.join(', ') : s.owner.split('@')[0]}</small>
                </th>
                {m.targets.map((t, j) => {
                  const self = t.kind === 'device' && t.dev === s
                  const c = m.cells[i][j]
                  const show = visible(c)
                  if (self) return <td key={j} className="cell cell-self" aria-label="same device" />
                  const pctW = show ? Math.round(capWeight(c) * 100) : 0
                  const dst = targetLabel(t)
                  return (
                    <td key={j} className="cell">
                      <button
                        type="button"
                        className={show ? (pctW > 60 ? 'on strong' : 'on') : 'off'}
                        style={show ? ({ '--w': pctW } as React.CSSProperties) : undefined}
                        aria-label={`${s.name} to ${dst}: ${show ? formatCaps(c) : 'denied'}`}
                        onMouseEnter={() => setHover({ s, t, caps: show ? c : [] })}
                        onFocus={() => setHover({ s, t, caps: show ? c : [] })}
                        onMouseLeave={() => setHover(null)}
                        onClick={() => {
                          const first = c.find((x) => x.hi - x.lo < 1000)
                          onTrace({
                            src: s.name,
                            dst: t.kind === 'device' ? t.dev.name : t.kind === 'range' ? t.label : 'autogroup:internet',
                            port: port !== null ? String(port) : first ? String(first.lo) : '443',
                            proto: first?.proto === 'udp' ? 'udp' : 'tcp',
                          })
                        }}
                      >{show ? shortCaps(c) : ''}</button>
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

// ---------- why ----------
function runTrace(policy: Policy, inv: Inventory, t: Trace) {
  const ctx = new Ctx(policy, inv)
  if (!t.src || !t.dst) return { error: 'Choose a source and a destination.' }
  const src = resolveSrc(ctx, t.src)
  if (typeof src === 'string') return { error: src }
  const targets = resolveTargets(ctx, t.dst)
  if (typeof targets === 'string') return { error: targets }
  if (targets.length !== 1) return { error: 'Choose one destination, not a whole group.' }
  const port = Number(t.port)
  if (!/^\d+$/.test(t.port) || port > 65535) return { error: 'Port must be a number from 0 to 65535.' }
  const target = targets[0]
  return {
    target,
    exp: explain(ctx, src, target, t.proto, port),
    ssh: target.kind === 'device' && t.sshUser ? sshEval(ctx, src, target.dev, t.sshUser) : undefined,
  }
}
function WhyView({ inv, trace, setTrace, traced, showPath }: { inv: Inventory; trace: Trace; setTrace: (t: Trace) => void; traced: ReturnType<typeof runTrace> | null; showPath: (p: string[], t?: Tone) => void }) {
  const set = (k: keyof Trace) => (e: { target: { value: string } }) => setTrace({ ...trace, [k]: e.target.value })
  return (
    <>
      <form className="why-form" onSubmit={(e) => e.preventDefault()}>
        <label><span className="mono-label">Source</span><input list="src-opts" value={trace.src} onChange={set('src')} placeholder="device, user or tag" /></label>
        <label><span className="mono-label">Destination</span><input list="dst-opts" value={trace.dst} onChange={set('dst')} placeholder="device, tag, host or IP" /></label>
        <label className="narrow"><span className="mono-label">Proto</span>
          <select value={trace.proto} onChange={set('proto')}>{['tcp', 'udp', 'icmp'].map((p) => <option key={p}>{p}</option>)}</select>
        </label>
        <label className="narrow"><span className="mono-label">Port</span><input inputMode="numeric" value={trace.port} onChange={set('port')} /></label>
        <label className="narrow"><span className="mono-label">SSH user</span><input value={trace.sshUser} onChange={set('sshUser')} /></label>
        <datalist id="src-opts">
          {inv.devices.map((d) => <option key={d.name} value={d.name} />)}
          {inv.users.map((u) => <option key={u.email} value={u.email} />)}
        </datalist>
        <datalist id="dst-opts">
          {inv.devices.map((d) => <option key={d.name} value={d.name} />)}
          {[...new Set(inv.devices.flatMap((d) => d.tags))].map((t) => <option key={t} value={t} />)}
          <option value="autogroup:internet" />
        </datalist>
      </form>
      {!traced || 'error' in traced ? <Empty title="Nothing to trace yet" body={traced && 'error' in traced ? traced.error ?? '' : 'Choose a source and destination.'} /> : (
        <>
          <div className={`verdict ${traced.exp.allowed ? 'v-ok' : 'v-no'}`} role="status">
            <span className="verdict-icon" aria-hidden="true">{traced.exp.allowed ? '✓' : '✕'}</span>
            <div>
              <strong>{traced.exp.allowed ? 'Allowed' : 'Denied'}</strong>
              <p>
                <code>{trace.src}</code> → <code>{trace.dst}</code> on <code>{trace.proto}:{trace.port}</code>.{' '}
                {traced.exp.allowed
                  ? `${traced.exp.hits.length} matching ${traced.exp.hits.length === 1 ? 'rule' : 'rules'}, highlighted in the editor.`
                  : traced.exp.near.length ? 'Tailscale denies by default and no rule covers this. The closest rules are below.' : 'Tailscale denies by default and no rule mentions this source or destination.'}
              </p>
              {traced.exp.caps.length > 0 && !traced.exp.allowed && <p className="muted">This pair can only use {formatCaps(traced.exp.caps)}.</p>}
            </div>
          </div>
          {traced.exp.hits.length > 0 && <h3 className="section-title">Matched</h3>}
          <ul className="rule-list">
            {traced.exp.hits.map((h, i) => (
              <li key={i}>
                <button type="button" className="rule hit" onClick={() => showPath([h.rule.path], 'hit')}>
                  <code>{pretty(h.rule.path)}</code>
                  <span>Source via <code>{h.srcSel.sel}</code>, destination via <code>{h.dst.raw}</code> ({formatCaps(h.dst.caps)})</span>
                </button>
              </li>
            ))}
          </ul>
          {traced.exp.notes.length > 0 && <ul className="notes">{[...new Set(traced.exp.notes)].map((n) => <li key={n}>{n.replace(/(acls|grants)\.(\d+)/g, '$1[$2]')}</li>)}</ul>}
          {traced.ssh && (
            <>
              <h3 className="section-title">Tailscale SSH as {trace.sshUser}</h3>
              <div className="ssh-line">
                <span className={`pill pill-${traced.ssh.action}`}>{traced.ssh.action === 'deny' ? '✕ deny' : traced.ssh.action === 'check' ? '! check' : '✓ accept'}</span>
                {traced.ssh.rule
                  ? <button type="button" className="linkish" onClick={() => showPath([traced.ssh!.rule!.path], 'hit')}><code>{pretty(traced.ssh.rule.path)}</code></button>
                  : <span className="muted">No ssh rule matches.</span>}
                <span className={traced.ssh.network22 ? 'muted' : 'warn-text'}>
                  {traced.ssh.network22 ? 'Network access on tcp:22 is allowed.' : traced.ssh.action === 'deny' ? 'tcp:22 is also not allowed.' : 'Blocked in practice: no acl or grant allows tcp:22.'}
                </span>
              </div>
            </>
          )}
          {traced.exp.near.length > 0 && <h3 className="section-title">Near misses</h3>}
          <ul className="rule-list">
            {traced.exp.near.map((n, i) => (
              <li key={i}>
                <button type="button" className="rule near" onClick={() => showPath([n.rule.path], 'near')}>
                  <code>{pretty(n.rule.path)}</code><span>{n.reason}</span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  )
}

// ---------- tests ----------
function TestsView({ results, showPath, onTrace }: { results: TestResult[]; showPath: (p: string[], t?: Tone) => void; onTrace: (t: Partial<Trace>) => void }) {
  if (!results.length) return <Empty title="This policy has no tests" body={'Add a "tests" or "sshTests" block. Tailscale rejects a save when one fails, so they protect access you depend on.'} />
  const pass = results.filter((r) => r.ok).length
  const asserts = results.flatMap((r) => r.assertions)
  return (
    <>
      <div className="tiles">
        <Tile label="Test blocks" value={`${pass}/${results.length}`} note="passing" />
        <Tile label="Assertions" value={`${asserts.filter((a) => a.ok).length}/${asserts.length}`} note="passing" />
        <Tile label="Save would be" value={pass === results.length ? 'Accepted' : 'Rejected'} note={pass === results.length ? 'all assertions hold' : 'Tailscale blocks failing tests'} />
      </div>
      <ul className="test-list">
        {results.map((r) => (
          <li key={r.path} className={r.ok ? 'test ok' : 'test bad'}>
            <button type="button" className="test-head" onClick={() => showPath([r.path], r.ok ? 'hit' : 'err')}>
              <span className={`pill ${r.ok ? 'pill-accept' : 'pill-deny'}`}>{r.ok ? '✓ pass' : '✕ fail'}</span>
              <code>{pretty(r.path)}</code>
              <span className="muted">from {r.src}</span>
            </button>
            {r.error && <p className="warn-text pad">{r.error}</p>}
            {r.assertions.length > 0 && (
              <table className="assert-table">
                <thead><tr><th scope="col">Destination</th><th scope="col">Expected</th><th scope="col">Actual</th><th scope="col">Rule</th></tr></thead>
                <tbody>
                  {r.assertions.map((a, i) => {
                    const hp = r.kind === 'tests' ? /^(.*):(\d+)$/.exec(a.dst) : null
                    return (
                      <tr key={i} className={a.ok ? '' : 'row-bad'}>
                        <td>
                          {hp
                            ? <button type="button" className="linkish" title="Trace this connection" onClick={() => onTrace({ src: r.src, dst: hp[1], port: hp[2] })}><code>{a.dst}</code></button>
                            : <code>{a.dst}</code>}
                          {a.error && <small className="warn-text"> {a.error}</small>}
                        </td>
                        <td>{a.expect}</td>
                        <td className={a.ok ? '' : 'strong-bad'}>{a.ok ? '✓ ' : '✕ '}{a.actual}</td>
                        <td>{a.rules.length ? a.rules.map((p) => <button key={p} type="button" className="linkish" onClick={() => showPath([p], a.ok ? 'hit' : 'err')}><code>{pretty(p)}</code></button>) : <span className="muted">none</span>}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </li>
        ))}
      </ul>
    </>
  )
}

// ---------- diff ----------
function DiffView({ policy, inv, old, setOld, text, sample, onTrace }: { policy: Policy; inv: Inventory; old: string; setOld: (s: string) => void; text: string; sample?: Sample; onTrace: (t: Partial<Trace>) => void }) {
  const [filter, setFilter] = useState<'all' | 'gained' | 'lost'>('all')
  const prev = useMemo(() => loadPolicy(old), [old])
  const rows = useMemo(() => (prev.policy ? diffPolicies(prev.policy, policy, inv) : []), [prev, policy, inv])
  const gained = rows.filter((r) => r.gained.length)
  const lost = rows.filter((r) => r.lost.length)
  const shown = filter === 'gained' ? gained : filter === 'lost' ? lost : rows
  const affected = new Set(rows.map((r) => r.src)).size
  const e = prev.parse.error
  return (
    <>
      <div className="diff-head">
        <div>
          <h3 className="section-title flush">Baseline policy</h3>
          <p className="muted">Paste the version currently live. The editor on the left is the proposed version.</p>
        </div>
        <div className="row-gap">
          {sample && <button type="button" className="btn" onClick={() => setOld(sample.previous)}>Reset to sample baseline</button>}
          <button type="button" className="btn" onClick={() => setOld(text)}>Use current as baseline</button>
        </div>
      </div>
      <div className="diff-editor">
        <Editor value={old} onChange={setOld} marks={[]} label="Baseline policy" />
      </div>
      {e ? <div className="ed-error" role="alert"><strong>Baseline line {e.line}, col {e.col}: {e.message}</strong></div> : (
        <>
          <div className="tiles">
            <Tile label="Connections gained" value={<span className="gain">+{gained.length}</span>} note="new source and destination pairs or ports" />
            <Tile label="Connections lost" value={<span className="lose">−{lost.length}</span>} note="could break something in use" />
            <Tile label="Devices affected" value={affected} note={`of ${inv.devices.length} in the inventory`} />
          </div>
          {!rows.length ? <Empty title="No change in network access" body="Both versions allow exactly the same connections for this inventory." /> : (
            <>
              <div className="segmented" role="group" aria-label="Filter changes">
                {(['all', 'gained', 'lost'] as const).map((f) => <button key={f} type="button" aria-pressed={filter === f} onClick={() => setFilter(f)}>{f}</button>)}
              </div>
              <div className="table-scroll">
                <table className="diff-table">
                  <thead><tr><th scope="col">From</th><th scope="col">To</th><th scope="col">Change</th><th scope="col">Before</th><th scope="col">After</th></tr></thead>
                  <tbody>
                    {shown.map((r) => (
                      <tr key={`${r.src}>${r.dst}`}>
                        <td><code>{r.src}</code></td>
                        <td>
                          <button type="button" className="linkish" title="Trace this connection" onClick={() => {
                            const first = [...r.gained, ...r.lost].find((c) => c.hi - c.lo < 1000)
                            onTrace({ src: r.src, dst: r.dst === 'internet' ? 'autogroup:internet' : r.dst, port: first ? String(first.lo) : '443', proto: first?.proto === 'udp' ? 'udp' : 'tcp' })
                          }}><code>{r.dst}</code></button>
                        </td>
                        <td>
                          {r.gained.length > 0 && <span className="chip chip-gain">+ {formatCaps(r.gained)}</span>}
                          {r.lost.length > 0 && <span className="chip chip-lose">− {formatCaps(r.lost)}</span>}
                        </td>
                        <td className="muted">{formatCaps(r.before) || 'none'}</td>
                        <td className="muted">{formatCaps(r.after) || 'none'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </>
  )
}

// ---------- lints ----------
const SEV: Record<Severity, { icon: string; label: string }> = { error: { icon: '✕', label: 'Error' }, warning: { icon: '!', label: 'Warning' }, info: { icon: 'i', label: 'Info' } }
function LintsView({ lints, showPath }: { lints: Problem[]; showPath: (p: string[], t?: Tone) => void }) {
  const [sev, setSev] = useState<Severity | 'all'>('all')
  if (!lints.length) return <Empty title="Nothing to flag" body="No unused definitions, broad rules or shadowed rules." />
  const shown = sev === 'all' ? lints : lints.filter((l) => l.severity === sev)
  const count = (s: Severity) => lints.filter((l) => l.severity === s).length
  return (
    <>
      <div className="segmented" role="group" aria-label="Filter by severity">
        <button type="button" aria-pressed={sev === 'all'} onClick={() => setSev('all')}>All {lints.length}</button>
        {(['error', 'warning', 'info'] as const).map((s) => <button key={s} type="button" aria-pressed={sev === s} onClick={() => setSev(s)}>{SEV[s].label} {count(s)}</button>)}
      </div>
      {!shown.length && <Empty title={`No ${sev} findings`} body="Choose another severity to see the rest." />}
      <ul className="lint-list">
        {shown.map((l, i) => (
          <li key={i}>
            <button type="button" className={`lint lint-${l.severity}`} disabled={!l.path} onClick={() => l.path && showPath([l.path], l.severity === 'error' ? 'err' : l.severity === 'warning' ? 'near' : 'info')}>
              <span className="lint-icon" aria-label={SEV[l.severity].label}>{SEV[l.severity].icon}</span>
              <span className="lint-body">
                <span>{l.message.replace(/(acls|grants|ssh)\.(\d+)/g, '$1[$2]')}</span>
                <small className="mono-label">{l.code}</small>
              </span>
            </button>
          </li>
        ))}
      </ul>
    </>
  )
}

// ---------- graph ----------
function GraphView({ policy, inv, onInfer }: { policy: Policy; inv: Inventory; onInfer: () => void }) {
  const graph = useMemo(() => buildGraph(policy, inv), [policy, inv])
  const [selected, setSelected] = useState<string | null>(null)
  const [packets, setPackets] = useState(true)
  if (!graph.nodes.length) return <Empty title="No identities to draw" body="The graph needs devices in the inventory." action={<button type="button" className="btn primary" onClick={onInfer}>Infer inventory from policy</button>} />
  const node: GNode | undefined = graph.nodes.find((n) => n.id === selected)
  const out = graph.edges.filter((e) => e.from === selected)
  const inc = graph.edges.filter((e) => e.to === selected)
  return (
    <>
      <div className="toolbar">
        <div className="legend">
          <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true"><circle cx="7" cy="7" r="6" className="lg" /></svg><span>User</span>
          <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true"><rect x="1" y="1" width="12" height="12" rx="3" className="lg" /></svg><span>Tag</span>
          <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true"><path d="M7 0 14 7 7 14 0 7Z" className="lg" /></svg><span>Subnet</span>
          <i className="dot dot-ok" /><span>Allowed packet</span>
          <i className="dot dot-no" /><span>Denied packet</span>
        </div>
        <label className="check"><input type="checkbox" checked={packets} onChange={(e) => setPackets(e.target.checked)} /> Simulate traffic</label>
      </div>
      <div className="graph-card dots">
        <LiveGraph graph={graph} policy={policy} inventory={inv} height={520} packets={packets} selected={selected} onSelect={setSelected} label={`Access graph with ${graph.nodes.length} identities and ${graph.edges.length} allowed paths`} />
      </div>
      {node ? (
        <div className="edge-lists">
          <div>
            <h3 className="section-title">{node.id} can reach</h3>
            <EdgeList rows={out.map((e) => [e.to, formatCaps(e.caps)])} empty="Nothing" />
          </div>
          <div>
            <h3 className="section-title">Reachable from</h3>
            <EdgeList rows={inc.map((e) => [e.from, formatCaps(e.caps)])} empty="Nobody" />
          </div>
        </div>
      ) : <p className="muted hint">Select a node to list its paths. Drag nodes to rearrange them. Keyboard: Tab to a node, then Enter.</p>}
    </>
  )
}
function EdgeList({ rows, empty }: { rows: [string, string][]; empty: string }) {
  if (!rows.length) return <p className="muted">{empty}</p>
  return <ul className="edge-list">{rows.map(([a, b]) => <li key={a}><code>{a}</code><span className="muted">{b}</span></li>)}</ul>
}

// ---------- inventory ----------
function ListInput({ value, onChange, label, placeholder }: { value: string[]; onChange: (v: string[]) => void; label: string; placeholder?: string }) {
  const parse = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean)
  const [raw, setRaw] = useState(value.join(', '))
  // Keep what's being typed (like a trailing comma) unless the value changed from outside.
  useEffect(() => { if (parse(raw).join() !== value.join()) setRaw(value.join(', ')) }, [value])
  return <input aria-label={label} placeholder={placeholder} value={raw} onChange={(e) => { setRaw(e.target.value); onChange(parse(e.target.value)) }} />
}
function InventoryView({ inv, setInv, onInfer, say }: { inv: Inventory; setInv: (i: Inventory) => void; onInfer: () => void; say: (m: string) => void }) {
  const [paste, setPaste] = useState('')
  const [pasteErr, setPasteErr] = useState('')
  const dev = (i: number, patch: Partial<Device>) => setInv({ ...inv, devices: inv.devices.map((d, j) => (j === i ? { ...d, ...patch } : d)) })
  const usr = (i: number, patch: Partial<Inventory['users'][number]>) => setInv({ ...inv, users: inv.users.map((u, j) => (j === i ? { ...u, ...patch } : u)) })
  const imp = () => {
    try {
      const i = inventoryFromStatus(JSON.parse(paste))
      setInv(i)
      setPaste('')
      setPasteErr('')
      say(`Imported ${i.devices.length} devices. Set roles below, since status output doesn't include them.`)
    } catch (e) {
      setPasteErr(e instanceof SyntaxError ? `That isn't valid JSON: ${e.message}` : (e as Error).message)
    }
  }
  return (
    <>
      <div className="diff-head">
        <p className="muted">Group membership comes from the policy's <code>groups</code>. Everything else here is what the policy is evaluated against.</p>
        <button type="button" className="btn" onClick={onInfer}>Infer from policy</button>
      </div>
      <h3 className="section-title">Users <span className="count">{inv.users.length}</span></h3>
      <div className="table-scroll">
        <table className="inv-table">
          <thead><tr><th scope="col">Login</th><th scope="col">Role</th><th scope="col">Shared in</th><th><span className="sr-only">Remove</span></th></tr></thead>
          <tbody>
            {inv.users.map((u, i) => (
              <tr key={i}>
                <td><input aria-label="Login" value={u.email} onChange={(e) => usr(i, { email: e.target.value })} /></td>
                <td><select aria-label="Role" value={u.role} onChange={(e) => usr(i, { role: e.target.value as Role })}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select></td>
                <td className="center"><input type="checkbox" aria-label="Shared user" checked={!!u.shared} onChange={(e) => usr(i, { shared: e.target.checked })} /></td>
                <td><button type="button" className="btn ghost icon" aria-label={`Remove ${u.email}`} onClick={() => setInv({ ...inv, users: inv.users.filter((_, j) => j !== i) })}>✕</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <button type="button" className="btn add" onClick={() => setInv({ ...inv, users: [...inv.users, { email: '', role: 'member' }] })}>Add user</button>

      <h3 className="section-title">Devices <span className="count">{inv.devices.length}</span></h3>
      <div className="table-scroll">
        <table className="inv-table">
          <thead><tr><th scope="col">Name</th><th scope="col">Tailscale IP</th><th scope="col">Owner</th><th scope="col">Tags</th><th scope="col">Routes</th><th scope="col">Exit</th><th><span className="sr-only">Remove</span></th></tr></thead>
          <tbody>
            {inv.devices.map((d, i) => (
              <tr key={i}>
                <td><input aria-label="Device name" value={d.name} onChange={(e) => dev(i, { name: e.target.value })} /></td>
                <td><input aria-label="Tailscale IP" value={d.ip} aria-invalid={!!d.ip && !/^\d+\.\d+\.\d+\.\d+$|:/.test(d.ip)} onChange={(e) => dev(i, { ip: e.target.value.trim() })} /></td>
                <td><input aria-label="Owner" list="owners" value={d.owner} onChange={(e) => dev(i, { owner: e.target.value })} disabled={d.tags.length > 0} title={d.tags.length ? 'Tagged devices have no user identity' : undefined} /></td>
                <td><ListInput label="Tags" value={d.tags} placeholder="tag:prod" onChange={(tags) => dev(i, { tags })} /></td>
                <td><ListInput label="Routes" value={d.routes} placeholder="10.0.0.0/24" onChange={(routes) => dev(i, { routes })} /></td>
                <td className="center"><input type="checkbox" aria-label="Exit node" checked={!!d.exitNode} onChange={(e) => dev(i, { exitNode: e.target.checked })} /></td>
                <td><button type="button" className="btn ghost icon" aria-label={`Remove ${d.name}`} onClick={() => setInv({ ...inv, devices: inv.devices.filter((_, j) => j !== i) })}>✕</button></td>
              </tr>
            ))}
          </tbody>
        </table>
        <datalist id="owners">{inv.users.map((u) => <option key={u.email} value={u.email} />)}</datalist>
      </div>
      <button type="button" className="btn add" onClick={() => setInv({ ...inv, devices: [...inv.devices, { name: `device-${inv.devices.length + 1}`, ip: '', owner: inv.users[0]?.email ?? '', tags: [], routes: [] }] })}>Add device</button>

      <details className="import">
        <summary>Import from <code>tailscale status --json</code></summary>
        <p className="muted">Run the command on a device and paste the output. You only get the peers that device can see, and it replaces the inventory above.</p>
        <textarea aria-label="tailscale status JSON" rows={6} value={paste} onChange={(e) => setPaste(e.target.value)} spellCheck={false} placeholder='{"Self": {...}, "Peer": {...}, "User": {...}}' />
        {pasteErr && <p className="warn-text" role="alert">{pasteErr}</p>}
        <button type="button" className="btn" disabled={!paste.trim()} onClick={imp}>Import</button>
      </details>
    </>
  )
}
