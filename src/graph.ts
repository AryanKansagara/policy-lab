// Identity graph + a small hand-rolled force simulation (no DOM, so it is testable).
import { capsBetween, Ctx, identityOf, matrixTargets, mergeCaps, targetLabel, type Cap, type Device, type Inventory, type Policy, type Target } from './engine.ts'

export type NodeKind = 'user' | 'tag' | 'subnet' | 'internet'
export interface GNode { id: string; label: string; kind: NodeKind; devices: Device[]; target?: Target; x: number; y: number; vx: number; vy: number; fixed?: boolean }
export interface GEdge { from: string; to: string; caps: Cap[]; rules: string[] }
export interface Graph { nodes: GNode[]; edges: GEdge[] }

export function buildGraph(p: Policy, inv: Inventory): Graph {
  const ctx = new Ctx(p, inv)
  const nodes = new Map<string, GNode>()
  const blank = { x: 0, y: 0, vx: 0, vy: 0 }
  const endpoints: { id: string; target: Target; src?: Device }[] = []
  for (const t of matrixTargets(p, inv)) {
    if (t.kind === 'device') {
      const id = identityOf(t.dev)
      const n = nodes.get(id) ?? { id, label: id.includes('@') ? id.split('@')[0] : id, kind: t.dev.tags.length ? 'tag' as const : 'user' as const, devices: [], ...blank }
      n.devices.push(t.dev)
      nodes.set(id, n)
      endpoints.push({ id, target: t, src: t.dev })
    } else {
      const id = targetLabel(t)
      nodes.set(id, { id, label: id, kind: t.kind === 'range' ? 'subnet' : 'internet', devices: [], target: t, ...blank })
      endpoints.push({ id, target: t })
    }
  }
  const acc = new Map<string, GEdge>()
  for (const s of endpoints) {
    if (!s.src) continue
    for (const d of endpoints) {
      if (d.id === s.id) continue
      const { caps, hits } = capsBetween(ctx, s.src, d.target)
      if (!caps.length) continue
      const k = `${s.id}\u0000${d.id}`
      const e = acc.get(k) ?? { from: s.id, to: d.id, caps: [], rules: [] }
      e.caps = mergeCaps([...e.caps, ...caps])
      e.rules = [...new Set([...e.rules, ...hits.map((h) => h.rule.path)])]
      acc.set(k, e)
    }
  }
  return { nodes: [...nodes.values()], edges: [...acc.values()] }
}

/** Seed nodes on a circle so layout is deterministic for a given policy. */
export function seedLayout(g: Graph, w: number, h: number, prev?: Map<string, { x: number; y: number }>) {
  g.nodes.forEach((n, i) => {
    const old = prev?.get(n.id)
    const a = (i / Math.max(1, g.nodes.length)) * Math.PI * 2
    n.x = old?.x ?? w / 2 + Math.cos(a) * w * 0.32
    n.y = old?.y ?? h / 2 + Math.sin(a) * h * 0.32
    n.vx = n.vy = 0
  })
}

/** One tick: repulsion, edge springs, centering, bounds. O(n^2), fine for tailnet identity counts. */
export function stepLayout(g: Graph, w: number, h: number, alpha: number) {
  const { nodes, edges } = g
  const byId = new Map(nodes.map((n) => [n.id, n]))
  const area = (w * h) / Math.max(1, nodes.length)
  const rest = Math.min(190, Math.sqrt(area) * 0.72)
  for (let i = 0; i < nodes.length; i++)
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i]
      const b = nodes[j]
      const dx = a.x - b.x || 0.01 * (i + 1)
      const dy = a.y - b.y || 0.01 * (j + 1)
      const d2 = Math.max(100, dx * dx + dy * dy)
      const f = (rest * rest * alpha * 0.07) / d2
      a.vx += dx * f
      a.vy += dy * f
      b.vx -= dx * f
      b.vy -= dy * f
    }
  for (const e of edges) {
    const a = byId.get(e.from)
    const b = byId.get(e.to)
    if (!a || !b) continue
    const dx = b.x - a.x
    const dy = b.y - a.y
    const d = Math.hypot(dx, dy) || 1
    const f = ((d - rest) / d) * 0.035 * alpha
    a.vx += dx * f
    a.vy += dy * f
    b.vx -= dx * f
    b.vy -= dy * f
  }
  const marginX = 74
  for (const n of nodes) {
    n.vx += (w / 2 - n.x) * 0.012 * alpha
    n.vy += (h / 2 - n.y) * 0.016 * alpha
    n.vx *= 0.82
    n.vy *= 0.82
    if (n.fixed) { n.vx = n.vy = 0; continue }
    n.x = Math.min(w - marginX, Math.max(marginX, n.x + n.vx))
    n.y = Math.min(h - 44, Math.max(30, n.y + n.vy))
  }
}
