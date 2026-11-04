import { useEffect, useLayoutEffect, useMemo, useReducer, useRef, useState, type PointerEvent as RPE } from 'react'
import { capWeight, Ctx, explain, formatCaps, type Cap, type Inventory, type Policy, type Target } from './engine.ts'
import { seedLayout, stepLayout, type GEdge, type GNode, type Graph } from './graph.ts'

export interface PacketEvent { id: number; src: string; dst: string; proto: string; port: number; allowed: boolean; rules: string[]; selectors: string[] }
const NS = 'http://www.w3.org/2000/svg'
const R = 15
const COMMON = [22, 80, 443, 3000, 5432, 8080, 9100]
const pick = <T,>(a: T[]) => a[Math.floor(Math.random() * a.length)]

/** Quadratic edge bowed to one side, so A->B and B->A stay visually apart. */
function geom(a: { x: number; y: number }, b: { x: number; y: number }) {
  const dx = b.x - a.x
  const dy = b.y - a.y
  const d = Math.hypot(dx, dy) || 1
  const ux = dx / d
  const uy = dy / d
  const x1 = a.x + ux * (R + 2)
  const y1 = a.y + uy * (R + 2)
  const x2 = b.x - ux * (R + 7)
  const y2 = b.y - uy * (R + 7)
  const bow = Math.min(26, d * 0.1)
  const cx = (a.x + b.x) / 2 - uy * bow
  const cy = (a.y + b.y) / 2 + ux * bow
  return {
    d: `M${x1.toFixed(1)} ${y1.toFixed(1)}Q${cx.toFixed(1)} ${cy.toFixed(1)} ${x2.toFixed(1)} ${y2.toFixed(1)}`,
    at: (t: number) => ({ x: (1 - t) ** 2 * x1 + 2 * (1 - t) * t * cx + t ** 2 * x2, y: (1 - t) ** 2 * y1 + 2 * (1 - t) * t * cy + t ** 2 * y2 }),
  }
}
function portFor(caps: Cap[]): { proto: string; port: number } {
  const c = pick(caps.filter((x) => x.hi - x.lo < 1000))
  if (c) return { proto: c.proto === 'udp' ? 'udp' : 'tcp', port: c.lo }
  return { proto: 'tcp', port: pick(COMMON) }
}
const targetOf = (n: GNode): Target => n.target ?? { kind: 'device', dev: n.devices[0] }

function Shape({ kind }: { kind: GNode['kind'] }) {
  if (kind === 'user') return <circle r={R - 1} className="nd" />
  if (kind === 'tag') return <rect x={-R + 2} y={-R + 2} width={2 * R - 4} height={2 * R - 4} rx="5" className="nd" />
  if (kind === 'subnet') return <path d={`M0 ${-R}L${R} 0L0 ${R}L${-R} 0Z`} className="nd" />
  return <circle r={R - 1} className="nd nd-net" />
}

export function LiveGraph({ graph, policy, inventory, height = 480, packets, onEvent, selected, onSelect, label }: {
  graph: Graph
  policy: Policy
  inventory: Inventory
  height?: number
  packets?: boolean
  onEvent?: (e: PacketEvent) => void
  selected?: string | null
  onSelect?: (id: string | null) => void
  label: string
}) {
  const wrap = useRef<HTMLDivElement>(null)
  const layer = useRef<SVGGElement>(null)
  const svg = useRef<SVGSVGElement>(null)
  const [w, setW] = useState(800)
  const [, tick] = useReducer((x: number) => x + 1, 0)
  const alpha = useRef(0)
  const memory = useRef(new Map<string, { x: number; y: number }>())
  const onEventRef = useRef(onEvent)
  onEventRef.current = onEvent
  const byId = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph])

  useLayoutEffect(() => {
    const el = wrap.current
    if (!el) return
    const measure = () => setW(Math.max(280, Math.round(el.getBoundingClientRect().width)))
    measure()
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  useLayoutEffect(() => {
    seedLayout(graph, w, height, memory.current)
    for (let i = 0; i < 260; i++) stepLayout(graph, w, height, 1 - i / 280)
    alpha.current = 0.12
    tick()
  }, [graph, w, height])

  useEffect(() => {
    const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches
    const ctx = new Ctx(policy, inventory)
    const sources = graph.nodes.filter((n) => n.devices.length)
    type Live = { el: SVGCircleElement; a: GNode; b: GNode; born: number; dur: number; ok: boolean; rang: boolean }
    const live: Live[] = []
    const rings: { el: SVGCircleElement; born: number }[] = []
    let id = 0
    let nextSpawn = performance.now() + 300
    let raf = 0

    const ring = (n: GNode, ok: boolean, now: number) => {
      const el = document.createElementNS(NS, 'circle')
      el.setAttribute('class', ok ? 'ring ring-ok' : 'ring ring-no')
      el.setAttribute('cx', String(n.x))
      el.setAttribute('cy', String(n.y))
      layer.current?.appendChild(el)
      rings.push({ el, born: now })
    }
    const spawn = (now: number) => {
      let a: GNode | undefined
      let b: GNode | undefined
      let proto = 'tcp'
      let port = pick(COMMON)
      if (graph.edges.length && Math.random() < 0.62) {
        const e: GEdge = pick(graph.edges)
        a = byId.get(e.from)
        b = byId.get(e.to)
        if (Math.random() < 0.8) ({ proto, port } = portFor(e.caps))
      } else if (sources.length) {
        a = pick(sources)
        b = pick(graph.nodes.filter((n) => n !== a))
      }
      if (!a || !b) return
      // The verdict always comes from the real evaluator, never from the animation.
      const r = explain(ctx, a.devices[0], targetOf(b), proto, port)
      onEventRef.current?.({
        id: id++, src: a.label, dst: b.label, proto, port, allowed: r.allowed,
        rules: [...new Set(r.hits.map((h) => h.rule.path))],
        selectors: r.hits.flatMap((h) => [h.srcSel.path, h.dst.path]),
      })
      if (reduced) return
      const el = document.createElementNS(NS, 'circle')
      el.setAttribute('r', '4.5')
      el.setAttribute('class', r.allowed ? 'pk pk-ok' : 'pk pk-no')
      layer.current?.appendChild(el)
      live.push({ el, a, b, born: now, dur: r.allowed ? 950 : 1250, ok: r.allowed, rang: false })
    }
    const loop = (now: number) => {
      if (alpha.current > 0.015) {
        stepLayout(graph, w, height, alpha.current)
        alpha.current *= 0.975
        tick()
      }
      if (packets && now >= nextSpawn && document.visibilityState === 'visible') {
        spawn(now)
        nextSpawn = now + (reduced ? 2600 : 620)
      }
      for (let i = live.length - 1; i >= 0; i--) {
        const p = live[i]
        const q = (now - p.born) / p.dur
        const g = geom(p.a, p.b)
        let t: number
        let op = 1
        if (p.ok) t = q * q * (3 - 2 * q)
        else if (q < 0.6) t = 0.88 * (q / 0.6)
        else {
          // Hit the destination's boundary: bounce back and fade.
          if (!p.rang) { p.rang = true; ring(p.b, false, now) }
          const u = (q - 0.6) / 0.4
          t = 0.88 - u * 0.55
          op = 1 - u
        }
        if (q >= 1) {
          if (p.ok) ring(p.b, true, now)
          p.el.remove()
          live.splice(i, 1)
          continue
        }
        const pt = g.at(t)
        p.el.setAttribute('cx', pt.x.toFixed(1))
        p.el.setAttribute('cy', pt.y.toFixed(1))
        p.el.style.opacity = String(op)
      }
      for (let i = rings.length - 1; i >= 0; i--) {
        const r = rings[i]
        const q = (now - r.born) / 520
        if (q >= 1) { r.el.remove(); rings.splice(i, 1); continue }
        r.el.setAttribute('r', String(R + 2 + q * 15))
        r.el.style.opacity = String(1 - q)
      }
      raf = requestAnimationFrame(loop)
    }
    raf = requestAnimationFrame(loop)
    return () => {
      cancelAnimationFrame(raf)
      for (const p of live) p.el.remove()
      for (const r of rings) r.el.remove()
    }
  }, [graph, policy, inventory, packets, w, height, byId])

  useEffect(() => {
    return () => { memory.current = new Map(graph.nodes.map((n) => [n.id, { x: n.x, y: n.y }])) }
  }, [graph])

  // Pointer drag: a node stays pinned while held, then the layout relaxes.
  const drag = useRef<{ n: GNode; moved: boolean } | null>(null)
  const toSvg = (e: RPE) => {
    const r = svg.current!.getBoundingClientRect()
    return { x: e.clientX - r.left, y: e.clientY - r.top }
  }
  const down = (e: RPE, n: GNode) => {
    (e.currentTarget as Element).setPointerCapture(e.pointerId)
    drag.current = { n, moved: false }
    n.fixed = true
  }
  const move = (e: RPE) => {
    const d = drag.current
    if (!d) return
    const p = toSvg(e)
    d.n.x = Math.max(20, Math.min(w - 20, p.x))
    d.n.y = Math.max(20, Math.min(height - 20, p.y))
    d.moved = true
    alpha.current = 0.25
    tick()
  }
  const up = () => {
    const d = drag.current
    if (!d) return
    d.n.fixed = false
    drag.current = null
    if (!d.moved) onSelect?.(selected === d.n.id ? null : d.n.id)
  }

  const related = (e: GEdge) => !selected || e.from === selected || e.to === selected
  const neighbors = selected ? new Set(graph.edges.filter(related).flatMap((e) => [e.from, e.to])) : null

  return (
    <div ref={wrap} className="graph-wrap" style={{ height }}>
      <svg ref={svg} width={w} height={height} role="group" aria-label={label} onClick={(e) => { if (e.target === svg.current) onSelect?.(null) }}>
        <defs>
          <marker id="arrow" viewBox="0 0 8 8" refX="6" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0 0.8 7 4 0 7.2Z" className="arrow" />
          </marker>
        </defs>
        <g>
          {graph.edges.map((e) => {
            const a = byId.get(e.from)
            const b = byId.get(e.to)
            if (!a || !b) return null
            const g = geom(a, b)
            const on = related(e)
            const mid = g.at(0.55)
            return (
              <g key={`${e.from}>${e.to}`} className={on ? (selected ? 'edge edge-on' : 'edge') : 'edge edge-dim'}>
                <path d={g.d} markerEnd="url(#arrow)" style={{ strokeWidth: 1 + capWeight(e.caps) * 1.1 }} />
                {selected && on && <text x={mid.x} y={mid.y} className="edge-label">{formatCaps(e.caps)}</text>}
                <title>{`${a.label} to ${b.label}: ${formatCaps(e.caps)}`}</title>
              </g>
            )
          })}
        </g>
        <g ref={layer} />
        <g>
          {graph.nodes.map((n) => (
            <g
              key={n.id}
              transform={`translate(${n.x.toFixed(1)} ${n.y.toFixed(1)})`}
              className={`node node-${n.kind}${selected === n.id ? ' node-sel' : ''}${neighbors && !neighbors.has(n.id) ? ' node-dim' : ''}`}
              tabIndex={onSelect ? 0 : undefined}
              role={onSelect ? 'button' : undefined}
              aria-pressed={onSelect ? selected === n.id : undefined}
              aria-label={onSelect ? `${n.id}, ${n.kind}` : undefined}
              onPointerDown={(e) => down(e, n)}
              onPointerMove={move}
              onPointerUp={up}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect?.(selected === n.id ? null : n.id) } }}
            >
              <Shape kind={n.kind} />
              <text y={R + 14} className="node-label">{n.label}</text>
            </g>
          ))}
        </g>
      </svg>
    </div>
  )
}
