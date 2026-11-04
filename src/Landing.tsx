import { useMemo, useRef, useState } from 'react'
import { capWeight, computeMatrix, diffPolicies, formatCaps, lint, loadPolicy, targetLabel, type Policy } from './engine.ts'
import { Editor, type Mark } from './Editor.tsx'
import { LiveGraph, type PacketEvent } from './LiveGraph.tsx'
import { buildGraph } from './graph.ts'
import { SAMPLES } from './samples.ts'
import { Brand, Footer, Link, ThemeToggle } from './ui.tsx'

const pretty = (p: string) => p.replace(/\.(\d+)/g, '[$1]')
const startup = SAMPLES[0]
const homelab = SAMPLES[1]
const enterprise = SAMPLES[2]

function Hero() {
  const loaded = useMemo(() => loadPolicy(startup.policy), [])
  const policy = loaded.policy as Policy
  const graph = useMemo(() => buildGraph(policy, startup.inventory), [policy])
  const [log, setLog] = useState<PacketEvent[]>([])
  const [active, setActive] = useState<PacketEvent | null>(null)
  const counts = useRef({ ok: 0, no: 0 })
  const onEvent = (e: PacketEvent) => {
    counts.current[e.allowed ? 'ok' : 'no']++
    setLog((l) => [e, ...l].slice(0, 7))
    if (e.allowed) setActive(e)
  }
  const marks: Mark[] = useMemo(() => {
    if (!active) return []
    const span = (p: string) => loaded.parse.spans.get(p)
    return [
      ...active.rules.flatMap((p) => { const s = span(p); return s ? [{ ...s, tone: 'hit' as const }] : [] }),
      ...active.selectors.flatMap((p) => { const s = span(p); return s ? [{ ...s, tone: 'hit' as const, inline: true }] : [] }),
    ]
  }, [active, loaded])
  const first = active?.rules[0]
  return (
    <div className="hero-stage">
      <div className="stage-col stage-code">
        <div className="stage-head"><span className="mono-label">policy.hujson</span></div>
        <Editor value={startup.policy} marks={marks} revealOffset={first ? loaded.parse.spans.get(first)?.start : undefined} revealNonce={active?.id} label="Sample policy" peek />
      </div>
      <div className="stage-col stage-graph dots">
        <div className="stage-head">
          <span className="mono-label">Acme Robotics tailnet</span>
          <span className="stage-legend"><i className="dot dot-ok" />allowed <i className="dot dot-no" />denied</span>
        </div>
        <LiveGraph graph={graph} policy={policy} inventory={startup.inventory} height={470} packets onEvent={onEvent} label="Animated graph of a sample tailnet. Packets travel along allowed paths and bounce off denied ones." />
      </div>
      <div className="stage-col stage-log">
        <div className="stage-head"><span className="mono-label">Decisions</span></div>
        <ol className="packet-log" aria-hidden="true">
          {log.map((e) => (
            <li key={e.id} className={e.allowed ? 'ok' : 'no'}>
              <span className="verdict-chip">{e.allowed ? '✓ allow' : '✕ deny'}</span>
              <span className="pl-path">{e.src} → {e.dst}</span>
              <span className="pl-meta">{e.proto}:{e.port}{e.rules[0] ? ` · ${pretty(e.rules[0])}` : ' · no rule'}</span>
            </li>
          ))}
        </ol>
      </div>
    </div>
  )
}

function MiniMatrix() {
  const m = useMemo(() => computeMatrix(loadPolicy(homelab.policy).policy as Policy, homelab.inventory), [])
  return (
    <div className="mini-matrix" role="img" aria-label="Small access matrix for the homelab sample" style={{ gridTemplateColumns: `repeat(${m.targets.length}, 1fr)` }}>
      {m.cells.flatMap((row, i) => row.map((c, j) => <i key={`${i}-${j}`} style={{ '--w': Math.round(capWeight(c) * 100) } as React.CSSProperties} className={c.length ? 'on' : ''} title={`${m.sources[i].name} to ${targetLabel(m.targets[j])}`} />))}
    </div>
  )
}
function MiniLints() {
  const items = useMemo(() => lint(loadPolicy(startup.policy).policy as Policy, startup.inventory).filter((l) => l.severity === 'warning').slice(0, 3), [])
  return <ul className="mini-list">{items.map((l, i) => <li key={i}><span className="lint-icon lint-warning-icon" aria-hidden="true">!</span>{l.message.replace(/acls\.(\d+)/g, 'acls[$1]')}</li>)}</ul>
}
function MiniDiff() {
  const rows = useMemo(() => {
    const a = loadPolicy(enterprise.previous).policy as Policy
    const b = loadPolicy(enterprise.policy).policy as Policy
    return diffPolicies(a, b, enterprise.inventory)
  }, [])
  return (
    <ul className="mini-list mono">
      {rows.slice(0, 4).map((r) => (
        <li key={r.src + r.dst}>
          <span className={r.gained.length ? 'gain' : 'lose'}>{r.gained.length ? '+' : '−'}</span> {r.src} → {r.dst} <span className="muted">{formatCaps(r.gained.length ? r.gained : r.lost)}</span>
        </li>
      ))}
    </ul>
  )
}

const FEATURES = [
  { title: 'Access matrix', body: 'Every device against every destination, with subnets and exit nodes. Filter to one port to answer "who can SSH into prod?" at a glance.', visual: <MiniMatrix /> },
  { title: 'Why was this denied?', body: 'Pick a source, destination and port. See the verdict, the exact rules lit up in the editor, and the near misses that almost matched.', visual: <div className="mini-why"><span className="verdict-chip ok">✓ allow</span><code>alice-mbp → api-prod-1 tcp:443</code><code className="muted">acls[1] via group:eng, tag:prod:443</code></div> },
  { title: 'Blast radius for every change', body: 'Paste the live policy next to the proposed one and read which connections open and close, before the pull request merges.', visual: <MiniDiff /> },
  { title: 'Lints the save button will not give you', body: 'Unused groups and tags, tags without owners, rules that are fully shadowed, rules that match nobody, and root SSH without check mode.', visual: <MiniLints /> },
]

export default function Landing() {
  return (
    <div className="landing">
      <header className="topbar landing-bar">
        <Brand />
        <nav className="topbar-actions" aria-label="Main">
          <a className="navlink" href="#features">Features</a>
          <a className="navlink" href="#samples">Samples</a>
          <ThemeToggle />
          <Link href="/app" className="btn primary">Open the lab</Link>
        </nav>
      </header>
      <main>
        <section className="hero">
          <p className="mono-label eyebrow">Tailnet policy simulator</p>
          <h1>See who can reach what, before you save the policy</h1>
          <p className="lede">
            One edit to a tailnet policy file can quietly open production to the whole company. Policy Lab evaluates your HuJSON against your users and devices, so you can read the result instead of guessing it.
          </p>
          <div className="hero-cta">
            <Link href="/app" className="btn primary large">Open the lab</Link>
            <Link href="/app?sample=enterprise" className="btn large">Try the enterprise sample</Link>
          </div>
          <Hero />
          <p className="stage-caption">This is the real evaluator running on the sample policy. Every packet gets its verdict from the same code the lab uses.</p>
        </section>

        <section className="band" aria-labelledby="pain">
          <div className="band-in two">
            <h2 id="pain">Policy files fail quietly</h2>
            <div className="prose">
              <p>A policy file decides what every device on your network can touch, and it grows one pull request at a time. Rules accumulate, tags outlive their servers, and nobody can say for certain what <code>group:eng</code> reaches today.</p>
              <p>Tests catch what you thought to assert. They can't tell you that this change also gave the contractor group a path to the database. Policy Lab answers that question for every pair of devices.</p>
            </div>
          </div>
        </section>

        <section id="features" className="features" aria-label="Features">
          {FEATURES.map((f) => (
            <article key={f.title} className="feature">
              <div className="feature-visual dots">{f.visual}</div>
              <h3>{f.title}</h3>
              <p>{f.body}</p>
            </article>
          ))}
        </section>

        <section className="band" aria-labelledby="coverage">
          <div className="band-in">
            <h2 id="coverage">Built on the documented syntax</h2>
            <dl className="coverage">
              <div><dt>Selectors</dt><dd>Users, <code>group:</code>, <code>tag:</code>, <code>hosts</code>, <code>ipset:</code>, CIDRs and autogroups including <code>self</code>, <code>member</code>, <code>tagged</code>, <code>internet</code>, <code>shared</code> and admin roles.</dd></div>
              <div><dt>Rules</dt><dd><code>acls</code> with ports and <code>proto</code>, <code>grants</code> with <code>ip</code>, <code>app</code> and <code>via</code>, <code>ssh</code> with check and accept, plus <code>autoApprovers</code>.</dd></div>
              <div><dt>Assertions</dt><dd>Your <code>tests</code> and <code>sshTests</code> blocks run as written, with each failure linked to the rule behind it.</dd></div>
              <div><dt>Privacy</dt><dd>Everything runs in your browser. Share links keep the policy in the URL fragment, which never reaches a server.</dd></div>
            </dl>
          </div>
        </section>

        <section id="samples" className="samples" aria-labelledby="samples-title">
          <h2 id="samples-title">Start from a real shape of tailnet</h2>
          <div className="sample-grid">
            {SAMPLES.map((s) => (
              <Link key={s.id} href={`/app?sample=${s.id}`} className="sample-card">
                <strong>{s.name}</strong>
                <span>{s.blurb}</span>
                <small className="mono-label">{s.inventory.devices.length} devices · {s.inventory.users.length} users</small>
              </Link>
            ))}
          </div>
          <p className="muted disclaimer">Policy Lab reimplements the semantics in Tailscale's public documentation. It isn't Tailscale's own evaluator, so check anything critical against the admin console's preview and your tailnet's tests.</p>
        </section>
      </main>
      <Footer />
    </div>
  )
}
