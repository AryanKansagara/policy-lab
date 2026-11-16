// Tailnet policy evaluation engine: groups, tagOwners, hosts, ipsets, autogroups,
// acls, grants, ssh, tests/sshTests, access matrix, diffs and lints.
import { parseHuJSON, type Json, type ParseResult } from './hujson.ts'

export type Role = 'owner' | 'admin' | 'network-admin' | 'it-admin' | 'billing-admin' | 'auditor' | 'member'
export const ROLES: Role[] = ['owner', 'admin', 'network-admin', 'it-admin', 'billing-admin', 'auditor', 'member']
export interface User { email: string; role: Role; shared?: boolean }
export interface Device { name: string; ip: string; owner: string; tags: string[]; routes: string[]; exitNode?: boolean }
export interface Inventory { users: User[]; devices: Device[] }

export interface Cap { proto: string; lo: number; hi: number } // proto '*' = every protocol
export interface Sel { sel: string; path: string }
export interface DstEntry { alias: string; caps: Cap[]; path: string; raw: string }
export interface NetRule {
  kind: 'acl' | 'grant'
  index: number
  path: string
  src: Sel[]
  dst: DstEntry[]
  via?: string[]
  app?: string[]
  posture?: string[] // srcPosture names; empty means defaultSrcPosture applies
}
export interface SshRule { index: number; path: string; action: 'accept' | 'check'; src: Sel[]; dst: Sel[]; users: string[]; checkPeriod?: string }
export interface TestDef { index: number; path: string; src: string; proto: string; accept: string[]; deny: string[]; attrs?: Record<string, Json> }
export interface SshTestDef { index: number; path: string; src: string; dst: string[]; accept: string[]; check: string[]; deny: string[]; attrs?: Record<string, Json> }
export type Severity = 'error' | 'warning' | 'info'
export interface Problem { severity: Severity; code: string; message: string; path?: string }

export interface Policy {
  groups: Record<string, string[]>
  tagOwners: Record<string, string[]>
  hosts: Record<string, string>
  ipsets: Record<string, string[]>
  rules: NetRule[]
  ssh: SshRule[]
  tests: TestDef[]
  sshTests: SshTestDef[]
  autoApprovers: { routes: Record<string, string[]>; exitNode: string[] }
  postures: Record<string, string[]>
  defaultSrcPosture: string[]
  problems: Problem[]
}

export interface Loaded { parse: ParseResult; policy?: Policy }

// ---------- address helpers ----------
// Addresses are 128-bit BigInts; IPv4 lives in the IPv4-mapped block ::ffff:0:0/96 so one range type covers both families.
type Range = { lo: number; hi: number } // ports
export type ARange = { lo: bigint; hi: bigint } // addresses
const V4_BASE = 0xffffn << 32n
const ip4 = (s: string): bigint | null => {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s)
  if (!m) return null
  const p = m.slice(1).map(Number)
  if (p.some((x) => x > 255)) return null
  return V4_BASE + BigInt(((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3])
}
const ip6 = (s0: string): bigint | null => {
  let s = s0.replace(/%.*$/, '').toLowerCase()
  if (!/^[0-9a-f:.]+$/.test(s) || !s.includes(':')) return null
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(s) // embedded IPv4 tail, as in ::ffff:1.2.3.4
  if (v4) {
    const n = ip4(v4[1])
    if (n === null) return null
    const x = Number(n - V4_BASE)
    s = `${s.slice(0, -v4[1].length)}${(x >>> 16).toString(16)}:${(x & 0xffff).toString(16)}`
  }
  const halves = s.split('::')
  if (halves.length > 2) return null
  const part = (h: string) => (h ? h.split(':') : [])
  const head = part(halves[0])
  const rest = halves.length === 2 ? part(halves[1]) : []
  const groups = halves.length === 2 ? [...head, ...Array(Math.max(0, 8 - head.length - rest.length)).fill('0'), ...rest] : head
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null
  return groups.reduce((acc, g) => (acc << 16n) + BigInt(parseInt(g, 16)), 0n)
}
const ipAddr = (s: string) => ip4(s) ?? ip6(s)
export function parseCidr(s: string): ARange | null {
  const [a, b, extra] = s.split('/')
  if (extra !== undefined) return null
  const v4 = ip4(a)
  const base = v4 ?? ip6(a)
  if (base === null) return null
  if (b === undefined) return { lo: base, hi: base }
  const max = v4 !== null ? 32 : 128
  const bits = Number(b)
  if (!/^\d+$/.test(b) || bits > max) return null
  const size = 1n << BigInt(max - bits)
  const lo = (base / size) * size
  return { lo, hi: lo + size - 1n }
}
const isAddrLiteral = (s: string) => parseCidr(s) !== null
const within = (r: ARange, outer: ARange) => r.lo >= outer.lo && r.hi <= outer.hi
const TAILNET = ['100.64.0.0/10', 'fd7a:115c:a1e0::/48'].map((c) => parseCidr(c)!)
export const inTailnet = (r: ARange) => TAILNET.some((t) => within(r, t))
const NON_PUBLIC = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/3', '::/127', 'fc00::/7', 'fe80::/10', 'ff00::/8'].map((c) => parseCidr(c)!)
/** autogroup:internet covers public addresses only: not private, CGNAT, link-local, loopback or multicast. */
export const isPublic = (r: ARange) => !NON_PUBLIC.some((n) => n.lo <= r.hi && n.hi >= r.lo)

// ---------- ports / protocols ----------
const PROTO_NUM: Record<string, string> = { '1': 'icmp', '6': 'tcp', '17': 'udp', '58': 'ipv6-icmp', '132': 'sctp', '47': 'gre', '50': 'esp', '51': 'ah', '2': 'igmp' }
const normProto = (p: string) => {
  const l = p.toLowerCase()
  return PROTO_NUM[l] ?? l
}
export function parsePorts(spec: string): Range[] | null {
  if (spec === '*') return [{ lo: 0, hi: 65535 }]
  const out: Range[] = []
  for (const part of spec.split(',')) {
    const m = /^(\d+)(?:-(\d+))?$/.exec(part.trim())
    if (!m) return null
    const lo = Number(m[1])
    const hi = m[2] ? Number(m[2]) : lo
    if (hi > 65535 || lo > hi) return null
    out.push({ lo, hi })
  }
  return out
}
export function splitHostPort(s: string): { alias: string; ports: string } | null {
  const b = /^\[([^\]]+)\]:(.+)$/.exec(s)
  if (b) return { alias: b[1], ports: b[2] }
  const i = s.lastIndexOf(':')
  if (i <= 0) return null
  return { alias: s.slice(0, i), ports: s.slice(i + 1) }
}
/** Grant `ip` entries: "*", "443", "tcp:443", "udp:*", "icmp:*", "80-90", "tcp:80,443". */
export function parseIpCap(s: string): Cap[] | null {
  if (s === '*') return [{ proto: '*', lo: 0, hi: 65535 }]
  const i = s.indexOf(':')
  const proto = i >= 0 ? normProto(s.slice(0, i)) : null
  const ports = parsePorts(i >= 0 ? s.slice(i + 1) : s)
  if (!ports) return null
  const protos = proto ? [proto] : ['tcp', 'udp']
  return protos.flatMap((p) => ports.map((r) => ({ proto: p, ...r })))
}

export function mergeCaps(caps: Cap[]): Cap[] {
  if (caps.some((c) => c.proto === '*' && c.lo === 0 && c.hi === 65535)) return [{ proto: '*', lo: 0, hi: 65535 }]
  const sorted = [...caps].sort((a, b) => (a.proto < b.proto ? -1 : a.proto > b.proto ? 1 : a.lo - b.lo))
  const out: Cap[] = []
  for (const c of sorted) {
    const last = out[out.length - 1]
    if (last && last.proto === c.proto && c.lo <= last.hi + 1) last.hi = Math.max(last.hi, c.hi)
    else out.push({ ...c })
  }
  return out
}
/** A minus B. A '*' cap is only reduced by '*' caps in B (shown as "other protocols"). */
export function subtractCaps(a: Cap[], b: Cap[]): Cap[] {
  const out: Cap[] = []
  for (const c of mergeCaps(a)) {
    let pieces: Range[] = [{ lo: c.lo, hi: c.hi }]
    for (const d of b) {
      if (!(d.proto === '*' || d.proto === c.proto)) continue
      pieces = pieces.flatMap((p) => {
        if (d.hi < p.lo || d.lo > p.hi) return [p]
        const r: Range[] = []
        if (d.lo > p.lo) r.push({ lo: p.lo, hi: d.lo - 1 })
        if (d.hi < p.hi) r.push({ lo: d.hi + 1, hi: p.hi })
        return r
      })
    }
    out.push(...pieces.map((p) => ({ proto: c.proto, ...p })))
  }
  return out
}
/** Tailscale allows ICMP between two addresses whenever any other traffic is allowed between them. */
export function capsAllow(caps: Cap[], proto: string, port: number) {
  const p = normProto(proto)
  if (p === 'icmp' || p === 'ipv6-icmp') return caps.length > 0
  return caps.some((c) => (c.proto === '*' || c.proto === p) && port >= c.lo && port <= c.hi)
}
export function formatCaps(caps: Cap[]): string {
  const m = mergeCaps(caps)
  if (!m.length) return ''
  if (m.length === 1 && m[0].proto === '*' && m[0].lo === 0 && m[0].hi === 65535) return 'all'
  const by = new Map<string, string[]>()
  for (const c of m) {
    const s = c.lo === 0 && c.hi === 65535 ? '*' : c.lo === c.hi ? String(c.lo) : `${c.lo}-${c.hi}`
    by.set(c.proto, [...(by.get(c.proto) ?? []), s])
  }
  const tu = by.get('tcp')?.join(',')
  if (tu && tu === by.get('udp')?.join(',')) {
    by.delete('tcp')
    by.delete('udp')
    by.set('tcp+udp', [tu])
  }
  return [...by].map(([p, v]) => `${p === '*' ? 'any' : p}:${v.join(',')}`).join(' ')
}
export function capWeight(caps: Cap[]): number {
  const m = mergeCaps(caps)
  if (!m.length) return 0
  if (m[0].proto === '*') return 1
  const n = m.reduce((s, c) => s + (c.hi - c.lo + 1), 0)
  return Math.min(1, 0.3 + (Math.log10(n) / Math.log10(131072)) * 0.7)
}

// ---------- loading ----------
const KNOWN_TOP = new Set(['acls', 'grants', 'ssh', 'groups', 'tagOwners', 'hosts', 'ipsets', 'tests', 'sshTests', 'autoApprovers', 'nodeAttrs', 'postures', 'derpMap', 'disableIPv4', 'randomizeClientPort', 'OneCGNATRoute', 'defaultSrcPosture', 'attrs'])
const strs = (v: Json | undefined): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : typeof v === 'string' ? [v] : [])
const obj = (v: Json | undefined): Record<string, Json> => (v && typeof v === 'object' && !Array.isArray(v) ? v : {})
const arr = (v: Json | undefined): Json[] => (Array.isArray(v) ? v : [])

export function loadPolicy(text: string): Loaded {
  const parse = parseHuJSON(text)
  if (parse.error || parse.value === undefined) return { parse }
  const problems: Problem[] = []
  const root = obj(parse.value)
  if (parse.value === null || typeof parse.value !== 'object' || Array.isArray(parse.value))
    problems.push({ severity: 'error', code: 'shape', message: 'The policy must be a JSON object' })
  for (const k of Object.keys(root)) if (!KNOWN_TOP.has(k)) problems.push({ severity: 'warning', code: 'unknown-key', message: `Unknown top-level section "${k}"`, path: k })
  for (const d of parse.duplicates) problems.push({ severity: 'error', code: 'duplicate-key', message: `Duplicate key "${d.path.split('.').pop()}" (the later value silently wins)`, path: d.path })

  const recStrs = (v: Json | undefined) => Object.fromEntries(Object.entries(obj(v)).map(([k, x]) => [k, strs(x)]))
  const groups = recStrs(root.groups)
  const tagOwners = recStrs(root.tagOwners)
  const ipsets = recStrs(root.ipsets)
  const hosts = Object.fromEntries(Object.entries(obj(root.hosts)).filter(([, v]) => typeof v === 'string')) as Record<string, string>
  const sels = (v: Json | undefined, path: string): Sel[] => strs(v).map((sel, i) => ({ sel, path: `${path}.${i}` }))

  const rules: NetRule[] = []
  arr(root.acls).forEach((r0, index) => {
    const r = obj(r0)
    const path = `acls.${index}`
    const action = r.action ?? 'accept'
    if (action !== 'accept' && action !== 'allow') problems.push({ severity: 'error', code: 'acl-action', message: `ACL action must be "accept" (got ${JSON.stringify(action)})`, path })
    const src = sels(r.src ?? r.users, `${path}.${r.src ? 'src' : 'users'}`)
    const dstField = r.dst ? 'dst' : 'ports'
    const protos = r.proto === undefined ? ['tcp', 'udp'] : [normProto(String(r.proto))]
    const dst: DstEntry[] = []
    strs(r.dst ?? r.ports).forEach((raw, i) => {
      const dpath = `${path}.${dstField}.${i}`
      const hp = splitHostPort(raw)
      const ports = hp && parsePorts(hp.ports)
      if (!hp || !ports) {
        problems.push({ severity: 'error', code: 'dst-port', message: `"${raw}" needs a port: use "${raw}:*" or "${raw}:443"`, path: dpath })
        return
      }
      dst.push({ alias: hp.alias, raw, path: dpath, caps: protos.flatMap((p) => ports.map((x) => ({ proto: p, ...x }))) })
    })
    if (!src.length) problems.push({ severity: 'error', code: 'acl-shape', message: 'ACL rule has no "src"', path })
    if (!strs(r.dst ?? r.ports).length) problems.push({ severity: 'error', code: 'acl-shape', message: 'ACL rule has no "dst"', path })
    rules.push({ kind: 'acl', index, path, src, dst, posture: strs(r.srcPosture) })
  })
  arr(root.grants).forEach((g0, index) => {
    const g = obj(g0)
    const path = `grants.${index}`
    const caps: Cap[] = []
    strs(g.ip).forEach((s, i) => {
      const c = parseIpCap(s)
      if (!c) problems.push({ severity: 'error', code: 'grant-ip', message: `Invalid ip capability "${s}" (try "tcp:443", "udp:53" or "*")`, path: `${path}.ip.${i}` })
      else caps.push(...c)
    })
    const app = Object.keys(obj(g.app))
    if (!g.ip && !app.length) problems.push({ severity: 'error', code: 'grant-shape', message: 'Grant needs "ip" and/or "app"', path })
    const dst: DstEntry[] = strs(g.dst).map((alias, i) => ({ alias, raw: alias, path: `${path}.dst.${i}`, caps }))
    if (!strs(g.src).length) problems.push({ severity: 'error', code: 'grant-shape', message: 'Grant has no "src"', path })
    if (!dst.length) problems.push({ severity: 'error', code: 'grant-shape', message: 'Grant has no "dst"', path })
    for (const d of dst) {
      const hp = splitHostPort(d.alias)
      if (hp && parsePorts(hp.ports) && !isAddrLiteral(d.alias) && (hp.alias === '*' || hp.alias.includes(':') || hp.alias.includes('@') || isAddrLiteral(hp.alias)))
        problems.push({ severity: 'error', code: 'grant-dst-port', message: `Grant dst "${d.alias}" includes a port; grants put ports in "ip"`, path: d.path })
    }
    rules.push({ kind: 'grant', index, path, src: sels(g.src, `${path}.src`), dst, via: strs(g.via), app, posture: strs(g.srcPosture) })
  })

  const ssh: SshRule[] = arr(root.ssh).map((s0, index) => {
    const s = obj(s0)
    const path = `ssh.${index}`
    const action = s.action === 'check' ? 'check' : 'accept'
    if (s.action !== 'check' && s.action !== 'accept') problems.push({ severity: 'error', code: 'ssh-action', message: 'SSH action must be "accept" or "check"', path })
    return { index, path, action, src: sels(s.src, `${path}.src`), dst: sels(s.dst, `${path}.dst`), users: strs(s.users), checkPeriod: typeof s.checkPeriod === 'string' ? s.checkPeriod : undefined }
  })
  const tests: TestDef[] = arr(root.tests).map((t0, index) => {
    const t = obj(t0)
    // No proto means "TCP or UDP", per Tailscale's tests documentation.
    return { index, path: `tests.${index}`, src: String(t.src ?? ''), proto: t.proto ? normProto(String(t.proto)) : '', accept: strs(t.accept ?? t.allow), deny: strs(t.deny), attrs: t.srcPostureAttrs ? obj(t.srcPostureAttrs) : undefined }
  })
  const sshTests: SshTestDef[] = arr(root.sshTests).map((t0, index) => {
    const t = obj(t0)
    return { index, path: `sshTests.${index}`, src: String(t.src ?? ''), dst: strs(t.dst), accept: strs(t.accept), check: strs(t.check), deny: strs(t.deny), attrs: t.srcPostureAttrs ? obj(t.srcPostureAttrs) : undefined }
  })
  const aa = obj(root.autoApprovers)
  // A posture is a list of assertions, or (newer form) an object with an "assertions" list.
  const postures = Object.fromEntries(Object.entries(obj(root.postures)).map(([k, v]) => [k, Array.isArray(v) ? strs(v) : strs(obj(v).assertions)]))
  for (const [k, as] of Object.entries(postures)) as.forEach((a, i) => { if (!parseAssertion(a)) problems.push({ severity: 'error', code: 'posture-syntax', message: `Cannot read posture assertion "${a}"`, path: `postures.${k}.${i}` }) })
  const policy: Policy = { groups, tagOwners, hosts, ipsets, rules, ssh, tests, sshTests, autoApprovers: { routes: recStrs(aa.routes), exitNode: strs(aa.exitNode) }, postures, defaultSrcPosture: strs(root.defaultSrcPosture), problems }
  return { parse, policy }
}

// ---------- device posture ----------
// Assertions look like "node:os IN ['macos', 'windows']" or "node:tsVersion >= '1.60'".
export interface Assertion0 { attr: string; op: string; value?: Json }
export function parseAssertion(s: string): Assertion0 | null {
  const m = /^\s*([\w:.\-]+)\s+(IS NOT SET|IS SET|NOT IN|IN|==|!=|<=|>=|<|>)\s*(.*?)\s*$/.exec(s)
  if (!m) return null
  const [, attr, op, raw] = m
  if (op === 'IS SET' || op === 'IS NOT SET') return raw ? null : { attr, op }
  const v = parseHuJSON(raw.replace(/'([^']*)'/g, (_, x: string) => JSON.stringify(x)))
  if (v.error || v.value === undefined) return null
  if ((op === 'IN' || op === 'NOT IN') !== Array.isArray(v.value)) return null
  return { attr, op, value: v.value }
}
const versionParts = (x: Json) => (typeof x === 'string' && /^\d+(\.\d+)*/.test(x) ? x.split(/[.-]/).map((p) => parseInt(p, 10)) : null)
function compare(a: Json, b: Json): number {
  if (typeof a === 'number' && typeof b === 'number') return a - b
  const va = versionParts(a)
  const vb = versionParts(b)
  if (va && vb) {
    for (let i = 0; i < Math.max(va.length, vb.length); i++) {
      const d = (va[i] || 0) - (vb[i] || 0)
      if (d) return d
    }
    return 0
  }
  return String(a).localeCompare(String(b))
}
export function assertionHolds(s: string, attrs: Record<string, Json>): boolean {
  const a = parseAssertion(s)
  if (!a) return false
  const has = Object.prototype.hasOwnProperty.call(attrs, a.attr) && attrs[a.attr] !== null
  if (a.op === 'IS SET') return has
  if (a.op === 'IS NOT SET') return !has
  if (!has) return false
  const v = attrs[a.attr]
  if (a.op === 'IN') return (a.value as Json[]).some((x) => compare(v, x) === 0)
  if (a.op === 'NOT IN') return !(a.value as Json[]).some((x) => compare(v, x) === 0)
  const c = compare(v, a.value as Json)
  return a.op === '==' ? c === 0 : a.op === '!=' ? c !== 0 : a.op === '<' ? c < 0 : a.op === '<=' ? c <= 0 : a.op === '>' ? c > 0 : c >= 0
}
/** A rule's srcPosture (or the policy's defaultSrcPosture) passes when the device meets every assertion of any one listed posture. */
export function postureHolds(p: Policy, rule: NetRule, attrs: Record<string, Json>): boolean {
  const names = rule.posture?.length ? rule.posture : p.defaultSrcPosture
  if (!names.length) return true
  return names.some((n) => (p.postures[n] ?? []).every((a) => assertionHolds(a, attrs)))
}

// ---------- matching ----------
export type Target = { kind: 'device'; dev: Device } | { kind: 'range'; label: string; lo: bigint; hi: bigint } | { kind: 'service'; name: string } | { kind: 'internet' }
export const targetLabel = (t: Target) => (t.kind === 'device' ? t.dev.name : t.kind === 'range' ? t.label : t.kind === 'service' ? t.name : 'internet')
export const isTagged = (d: Device) => d.tags.length > 0

export class Ctx {
  p: Policy
  users: Map<string, User>
  inv: Inventory
  attrs?: Record<string, Json> // known source posture attributes (tests); undefined means postures are assumed to pass
  constructor(p: Policy, inv: Inventory, attrs?: Record<string, Json>) {
    this.p = p
    this.inv = inv
    this.attrs = attrs
    this.users = new Map(inv.users.map((u) => [u.email.toLowerCase(), u]))
  }
  user(email: string): User {
    return this.users.get(email.toLowerCase()) ?? { email, role: 'member' }
  }
  /** Address ranges for IP-ish selectors (IP, CIDR, host alias, ipset); null if not an address selector. */
  addr(sel: string, seen = new Set<string>()): { add: ARange[]; remove: ARange[] } | null {
    if (seen.has(sel)) return { add: [], remove: [] }
    seen.add(sel)
    const r = parseCidr(sel)
    if (r) return { add: [r], remove: [] }
    if (sel in this.p.hosts) {
      const h = parseCidr(this.p.hosts[sel])
      return { add: h ? [h] : [], remove: [] }
    }
    if (sel.startsWith('ipset:')) {
      const out = { add: [] as ARange[], remove: [] as ARange[] }
      for (const e of this.p.ipsets[sel] ?? []) {
        const m = /^(add|remove)\s+(.+)$/.exec(e.trim())
        const op = m ? m[1] : 'add'
        let ref = (m ? m[2] : e).trim()
        if (ref.startsWith('host:')) ref = ref.slice(5)
        const sub = this.addr(ref, seen)
        if (!sub) continue
        if (op === 'add') { out.add.push(...sub.add); out.remove.push(...sub.remove) } else out.remove.push(...sub.add)
      }
      return out
    }
    return null
  }
  addrHas(sel: string, ip: string): boolean | null {
    const a = this.addr(sel)
    if (!a) return null
    const n = ipAddr(ip)
    if (n === null) return this.p.hosts[sel] === ip || sel === ip
    return a.add.some((r) => n >= r.lo && n <= r.hi) && !a.remove.some((r) => n >= r.lo && n <= r.hi)
  }
  addrOverlaps(sel: string, t: ARange): boolean | null {
    const a = this.addr(sel)
    if (!a) return null
    const inside = (r: ARange) => within(t, r)
    return a.add.some((r) => r.lo <= t.hi && r.hi >= t.lo) && !a.remove.some(inside)
  }
  /** Identity selectors shared by src and dst. */
  identity(sel: string, d: Device): boolean {
    const tagged = isTagged(d)
    if (sel.startsWith('tag:')) return d.tags.includes(sel)
    if (sel === 'autogroup:tagged') return tagged
    if (tagged || !d.owner) return false
    const u = this.user(d.owner)
    if (sel.startsWith('group:')) {
      return (this.p.groups[sel] ?? []).some((m) => m.toLowerCase() === d.owner.toLowerCase())
    }
    if (sel === 'autogroup:member' || sel === 'autogroup:members') return !u.shared
    if (sel === 'autogroup:shared') return !!u.shared
    if (sel.startsWith('autogroup:')) {
      const role = sel.slice(10)
      return (ROLES as string[]).includes(role) && u.role === role
    }
    if (sel.startsWith('user:*@')) return !u.shared && d.owner.toLowerCase().endsWith(sel.slice(6).toLowerCase())
    return sel.includes('@') && sel.toLowerCase() === d.owner.toLowerCase()
  }
  srcMatch(sel: string, src: Device): boolean {
    if (sel === '*' || sel === 'autogroup:danger-all') return true
    const a = src.ip ? this.addrHas(sel, src.ip) : this.addr(sel) ? false : null
    if (a !== null) return a
    return this.identity(sel, src)
  }
  dstMatch(sel: string, src: Device, t: Target): boolean {
    if (t.kind === 'internet') return sel === 'autogroup:internet'
    if (t.kind === 'service') return sel === t.name
    if (t.kind === 'range' && sel === 'autogroup:internet') return isPublic(t)
    if (sel === 'autogroup:internet' || sel.startsWith('svc:')) return false
    if (t.kind === 'range') {
      if (sel === '*') return true
      return this.addrOverlaps(sel, t) ?? false
    }
    const d = t.dev
    if (sel === '*') return true
    if (sel === 'autogroup:self') return !isTagged(d) && !isTagged(src) && !!d.owner && d.owner.toLowerCase() === src.owner.toLowerCase()
    const a = d.ip ? this.addrHas(sel, d.ip) : this.addr(sel) ? false : null
    if (a !== null) return a
    return this.identity(sel, d)
  }
}

export interface Hit { rule: NetRule; srcSel: Sel; dst: DstEntry }

export function capsBetween(ctx: Ctx, src: Device, t: Target, rules = ctx.p.rules): { caps: Cap[]; hits: Hit[] } {
  const hits: Hit[] = []
  for (const rule of rules) {
    if (ctx.attrs && !postureHolds(ctx.p, rule, ctx.attrs)) continue
    const s = rule.src.find((x) => ctx.srcMatch(x.sel, src))
    if (!s) continue
    for (const d of rule.dst) if (d.caps.length && ctx.dstMatch(d.alias, src, t)) hits.push({ rule, srcSel: s, dst: d })
  }
  return { caps: mergeCaps(hits.flatMap((h) => h.dst.caps)), hits }
}

// ---------- matrix ----------
export interface Matrix { sources: Device[]; targets: Target[]; cells: Cap[][][] }
export function matrixTargets(p: Policy, inv: Inventory): Target[] {
  const t: Target[] = inv.devices.map((dev) => ({ kind: 'device', dev }))
  const seen = new Set<string>()
  for (const d of inv.devices)
    for (const r of d.routes) {
      const c = parseCidr(r)
      if (!c || seen.has(r) || r === '0.0.0.0/0' || r === '::/0') continue
      seen.add(r)
      t.push({ kind: 'range', label: r, ...c })
    }
  for (const name of new Set(p.rules.flatMap((r) => r.dst.map((d) => d.alias).filter((a) => a.startsWith('svc:'))))) t.push({ kind: 'service', name })
  const usesInternet = p.rules.some((r) => r.dst.some((d) => d.alias === 'autogroup:internet'))
  if (usesInternet || inv.devices.some((d) => d.exitNode)) t.push({ kind: 'internet' })
  return t
}
export function computeMatrix(p: Policy, inv: Inventory, rules = p.rules): Matrix {
  const ctx = new Ctx(p, inv)
  const targets = matrixTargets(p, inv)
  const cells = inv.devices.map((s) => targets.map((t) => (t.kind === 'device' && t.dev === s ? [] : capsBetween(ctx, s, t, rules).caps)))
  return { sources: inv.devices, targets, cells }
}

// ---------- why? ----------
export interface NearMiss { rule: NetRule; reason: string; paths: string[] }
export interface Explanation { allowed: boolean; hits: Hit[]; near: NearMiss[]; caps: Cap[]; notes: string[] }
export function explain(ctx: Ctx, src: Device, t: Target, proto: string, port: number): Explanation {
  const { caps, hits } = capsBetween(ctx, src, t)
  const covering = hits.filter((h) => capsAllow(h.dst.caps, proto, port))
  const near: NearMiss[] = []
  for (const rule of ctx.p.rules) {
    if (covering.some((h) => h.rule === rule)) continue
    const s = rule.src.find((x) => ctx.srcMatch(x.sel, src))
    const ds = rule.dst.filter((d) => ctx.dstMatch(d.alias, src, t))
    if (s && ds.length) {
      const allows = formatCaps(ds.flatMap((d) => d.caps))
      near.push({ rule, reason: allows ? `Source and destination match, but it only allows ${allows}` : 'Source and destination match, but it grants app capabilities only (no "ip")', paths: [s.path, ...ds.map((d) => d.path)] })
    } else if (s) near.push({ rule, reason: `Source matches via ${s.sel}, but no destination selects ${targetLabel(t)}`, paths: [s.path] })
    else if (ds.length) near.push({ rule, reason: `Destination matches via ${ds[0].alias}, but no source selects ${src.name}`, paths: ds.map((d) => d.path) })
  }
  const notes: string[] = []
  for (const h of covering) {
    if (h.rule.via?.length) notes.push(`${h.rule.path} only applies when routed via ${h.rule.via.join(', ')}`)
    if (!ctx.attrs && (h.rule.posture?.length || ctx.p.defaultSrcPosture.length)) notes.push(`${h.rule.path} also requires the source to pass ${(h.rule.posture?.length ? h.rule.posture : ctx.p.defaultSrcPosture).join(' or ')} (assumed here)`)
    if (h.rule.app?.length) notes.push(`${h.rule.path} also grants app capabilities: ${h.rule.app.join(', ')}`)
  }
  if (t.kind === 'range' && covering.length) notes.push('Subnet traffic also requires the route to be approved and the subnet router reachable')
  if (t.kind === 'internet' && covering.length) notes.push('Exit node traffic: autogroup:internet controls who may use exit nodes')
  if (t.kind === 'service' && covering.length) notes.push(`${t.name} also needs a host approved to serve it and the service to listen on that port`)
  return { allowed: covering.length > 0, hits: covering, near, caps, notes }
}

// ---------- ssh ----------
export interface SshResult { action: 'accept' | 'check' | 'deny'; rule?: SshRule; network22: boolean }
export function sshUserMatch(pattern: string, user: string, src: Device): boolean {
  if (pattern === user) return true
  if (pattern === 'autogroup:nonroot') return user !== 'root'
  const m = /^localpart:\*@(.+)$/.exec(pattern)
  if (m && !isTagged(src)) {
    const [local, domain] = src.owner.toLowerCase().split('@')
    return domain === m[1].toLowerCase() && user === local
  }
  return false
}
export function sshEval(ctx: Ctx, src: Device, dst: Device, user: string): SshResult {
  const network22 = capsAllow(capsBetween(ctx, src, { kind: 'device', dev: dst }).caps, 'tcp', 22)
  for (const r of ctx.p.ssh)
    if (r.src.some((s) => ctx.srcMatch(s.sel, src)) && r.dst.some((d) => ctx.dstMatch(d.sel, src, { kind: 'device', dev: dst })) && r.users.some((u) => sshUserMatch(u, user, src)))
      return { action: r.action, rule: r, network22 }
  return { action: 'deny', network22 }
}

// ---------- resolving test endpoints ----------
export function resolveSrc(ctx: Ctx, alias: string): Device | string {
  const { devices } = ctx.inv
  const byName = devices.find((d) => d.name === alias)
  if (byName) return byName
  if (alias.startsWith('tag:')) {
    const real = devices.find((d) => d.tags.includes(alias))
    return { name: alias, ip: real?.ip ?? '', owner: '', tags: [alias], routes: [] }
  }
  if (alias.includes('@') && !alias.includes(':')) {
    const real = devices.find((d) => !isTagged(d) && d.owner.toLowerCase() === alias.toLowerCase())
    return { name: alias, ip: real?.ip ?? '', owner: alias, tags: [], routes: [] }
  }
  const ip = ctx.p.hosts[alias] ?? alias
  if (parseCidr(ip)) return devices.find((d) => d.ip === ip) ?? { name: alias, ip, owner: '', tags: [], routes: [] }
  if (!alias.includes(':') && !alias.includes('@')) return `"${alias}" is neither a device in the inventory nor a host defined in "hosts"`
  return `Test src "${alias}" must be a user, group, tag, host or IP`
}
export function resolveTargets(ctx: Ctx, alias: string): Target[] | string {
  const { devices } = ctx.inv
  if (alias === 'autogroup:internet') return [{ kind: 'internet' }]
  if (alias.startsWith('svc:')) return [{ kind: 'service', name: alias }]
  const byName = devices.filter((d) => d.name === alias)
  if (byName.length) return byName.map((dev) => ({ kind: 'device', dev }))
  if (alias.startsWith('tag:') || (alias.includes('@') && !alias.includes(':'))) {
    const s = resolveSrc(ctx, alias) as Device
    return [{ kind: 'device', dev: s }]
  }
  if (alias.startsWith('group:')) {
    const members = ctx.p.groups[alias]
    if (!members) return `Unknown group "${alias}"`
    return members.map((m) => ({ kind: 'device', dev: resolveSrc(ctx, m) as Device }))
  }
  const ip = ctx.p.hosts[alias] ?? alias
  const r = parseCidr(ip)
  if (!r) return `Cannot resolve destination "${alias}"`
  if (r.lo === r.hi) {
    const dev = devices.find((d) => d.ip === ip)
    if (dev) return [{ kind: 'device', dev }]
  }
  return [{ kind: 'range', label: alias, ...r }]
}

// ---------- tests ----------
export interface Assertion { dst: string; expect: 'accept' | 'deny' | 'check'; actual: string; ok: boolean; rules: string[]; error?: string }
export interface TestResult { kind: 'tests' | 'sshTests'; index: number; path: string; src: string; ok: boolean; assertions: Assertion[]; error?: string }

/** Test sources may also be a group: every member is checked. */
export function resolveSrcs(ctx: Ctx, alias: string): Device[] | string {
  if (!alias.startsWith('group:')) {
    const s = resolveSrc(ctx, alias)
    return typeof s === 'string' ? s : [s]
  }
  const members = ctx.p.groups[alias]
  if (!members) return `Unknown group "${alias}"`
  if (!members.length) return `${alias} has no members to test`
  return members.map((m) => resolveSrc(ctx, m)).filter((d): d is Device => typeof d !== 'string')
}

// Tests know the source's posture: srcPostureAttrs, or no attributes at all when omitted.
const testCtx = (p: Policy, inv: Inventory, attrs?: Record<string, Json>) => new Ctx(p, inv, attrs ?? {})

export function runTests(p: Policy, inv: Inventory): TestResult[] {
  const out: TestResult[] = []
  for (const t of p.tests) {
    const ctx = testCtx(p, inv, t.attrs)
    const srcs = resolveSrcs(ctx, t.src)
    if (typeof srcs === 'string') { out.push({ kind: 'tests', index: t.index, path: t.path, src: t.src, ok: false, assertions: [], error: srcs }); continue }
    const assertions: Assertion[] = []
    const check = (dst: string, expect: 'accept' | 'deny') => {
      const hp = splitHostPort(dst)
      const port = hp && /^\d+$/.test(hp.ports) ? Number(hp.ports) : NaN
      if (!hp || Number.isNaN(port)) return assertions.push({ dst, expect, actual: '?', ok: false, rules: [], error: 'Test destinations need a single port, e.g. "tag:prod:443"' })
      if (hp.alias.includes('/')) return assertions.push({ dst, expect, actual: '?', ok: false, rules: [], error: 'Tests cannot use CIDR ranges; name a single IP or host' })
      const targets = resolveTargets(ctx, hp.alias)
      if (typeof targets === 'string') return assertions.push({ dst, expect, actual: '?', ok: false, rules: [], error: targets })
      const verdict = (src: Device, tg: Target) => {
        if (t.proto) return explain(ctx, src, tg, t.proto, port)
        const tcp = explain(ctx, src, tg, 'tcp', port)
        return tcp.allowed ? tcp : explain(ctx, src, tg, 'udp', port)
      }
      const results = srcs.flatMap((src) => targets.map((tg) => verdict(src, tg)))
      const allowedAll = results.every((r) => r.allowed)
      const allowedAny = results.some((r) => r.allowed)
      const ok = expect === 'accept' ? allowedAll : !allowedAny
      const actual = allowedAll ? 'accept' : allowedAny ? 'partial' : 'deny'
      assertions.push({ dst, expect, actual, ok, rules: [...new Set(results.flatMap((r) => r.hits.map((h) => h.rule.path)))] })
    }
    t.accept.forEach((d) => check(d, 'accept'))
    t.deny.forEach((d) => check(d, 'deny'))
    out.push({ kind: 'tests', index: t.index, path: t.path, src: t.src, ok: assertions.every((a) => a.ok), assertions })
  }
  for (const t of p.sshTests) {
    const ctx = testCtx(p, inv, t.attrs)
    // Tailscale's sshTests evaluator resolves a user, not a group (tailscale/tailscale#11790).
    const srcs = t.src.startsWith('group:') ? `sshTests src must be a user or tag, not a group (${t.src})` : resolveSrcs(ctx, t.src)
    if (typeof srcs === 'string') { out.push({ kind: 'sshTests', index: t.index, path: t.path, src: t.src, ok: false, assertions: [], error: srcs }); continue }
    const assertions: Assertion[] = []
    for (const dstAlias of t.dst) {
      const targets = resolveTargets(ctx, dstAlias)
      if (typeof targets === 'string') { assertions.push({ dst: dstAlias, expect: 'accept', actual: '?', ok: false, rules: [], error: targets }); continue }
      const devs = targets.flatMap((x) => (x.kind === 'device' ? [x.dev] : []))
      const want: [string, 'accept' | 'check' | 'deny'][] = [...t.accept.map((u) => [u, 'accept'] as [string, 'accept']), ...t.check.map((u) => [u, 'check'] as [string, 'check']), ...t.deny.map((u) => [u, 'deny'] as [string, 'deny'])]
      for (const [user, expect] of want) {
        const rs = srcs.flatMap((src) => devs.map((d) => sshEval(ctx, src, d, user)))
        const actuals = [...new Set(rs.map((r) => r.action))]
        const actual = actuals.length === 1 ? actuals[0] : actuals.join('/')
        assertions.push({ dst: `${user}@${dstAlias}`, expect, actual: actual || 'deny', ok: actuals.length === 1 && actuals[0] === expect, rules: [...new Set(rs.flatMap((r) => (r.rule ? [r.rule.path] : [])))] })
      }
    }
    out.push({ kind: 'sshTests', index: t.index, path: t.path, src: t.src, ok: assertions.every((a) => a.ok), assertions })
  }
  return out
}

// ---------- diff ----------
export interface DiffRow { src: string; dst: string; before: Cap[]; after: Cap[]; gained: Cap[]; lost: Cap[] }
export function diffPolicies(a: Policy, b: Policy, inv: Inventory): DiffRow[] {
  const ma = computeMatrix(a, inv)
  const mb = computeMatrix(b, inv)
  const index = (m: Matrix) => {
    const r = new Map<string, Cap[]>()
    m.sources.forEach((s, i) => m.targets.forEach((t, j) => m.cells[i][j].length && r.set(`${s.name}\u0000${targetLabel(t)}`, m.cells[i][j])))
    return r
  }
  const ia = index(ma)
  const ib = index(mb)
  const rows: DiffRow[] = []
  for (const k of new Set([...ia.keys(), ...ib.keys()])) {
    const before = ia.get(k) ?? []
    const after = ib.get(k) ?? []
    const gained = subtractCaps(after, before)
    const lost = subtractCaps(before, after)
    if (!gained.length && !lost.length) continue
    const [src, dst] = k.split('\u0000')
    rows.push({ src, dst, before, after, gained, lost })
  }
  return rows.sort((x, y) => x.src.localeCompare(y.src) || x.dst.localeCompare(y.dst))
}

// ---------- lints ----------
export function lint(p: Policy, inv: Inventory): Problem[] {
  const out: Problem[] = [...p.problems]
  const ctx = new Ctx(p, inv)
  const add = (severity: Severity, code: string, message: string, path?: string) => out.push({ severity, code, message, path })

  // references
  const refs: Sel[] = [
    ...p.rules.flatMap((r) => [...r.src, ...r.dst.map((d) => ({ sel: d.alias, path: d.path })), ...(r.via ?? []).map((v, i) => ({ sel: v, path: `${r.path}.via.${i}` }))]),
    ...p.ssh.flatMap((r) => [...r.src, ...r.dst]),
    ...Object.entries(p.tagOwners).flatMap(([t, os]) => os.map((sel, i) => ({ sel, path: `tagOwners.${t}.${i}` }))),
    ...Object.entries(p.autoApprovers.routes).flatMap(([c, os]) => os.map((sel, i) => ({ sel, path: `autoApprovers.routes.${c}.${i}` }))),
    ...p.autoApprovers.exitNode.map((sel, i) => ({ sel, path: `autoApprovers.exitNode.${i}` })),
  ]
  const testRefs = [...p.tests.flatMap((t) => [t.src, ...[...t.accept, ...t.deny].map((d) => splitHostPort(d)?.alias ?? d)]), ...p.sshTests.flatMap((t) => [t.src, ...t.dst])]
  const all = [...refs.map((r) => r.sel), ...testRefs]
  const reported = new Set<string>()
  for (const r of refs) {
    const s = r.sel
    if (reported.has(s)) continue
    if (s.startsWith('group:') && !(s in p.groups)) { reported.add(s); add('error', 'undefined-group', `"${s}" is used but never defined in groups`, r.path) }
    else if (s.startsWith('tag:') && !(s in p.tagOwners)) { reported.add(s); add('error', 'tag-no-owner', `"${s}" is used but has no tagOwners entry, so no one can apply it`, r.path) }
    else if (s.startsWith('ipset:') && !(s in p.ipsets)) { reported.add(s); add('error', 'undefined-ipset', `"${s}" is not defined in ipsets`, r.path) }
    else if (s.startsWith('autogroup:') && !['member', 'members', 'tagged', 'self', 'internet', 'shared', 'danger-all', 'nonroot', ...ROLES].includes(s.slice(10))) { reported.add(s); add('error', 'unknown-autogroup', `Unknown autogroup "${s}"`, r.path) }
    else if (!s.includes(':') && !s.includes('@') && s !== '*' && !(s in p.hosts) && !isAddrLiteral(s)) { reported.add(s); add('error', 'unknown-host', `"${s}" is not a known host alias, user, group or tag`, r.path) }
  }
  for (const g of Object.keys(p.groups)) {
    if (!all.includes(g)) add('warning', 'unused-group', `${g} is defined but never referenced`, `groups.${g}`)
    for (const m of p.groups[g]) {
      if (m.startsWith('group:')) add('error', 'nested-group', `${g} contains ${m}; groups cannot contain other groups`, `groups.${g}`)
      else if (inv.users.length && !ctx.users.has(m.toLowerCase())) add('info', 'unknown-member', `${g} lists ${m}, who is not in the inventory`, `groups.${g}`)
    }
  }
  for (const t of Object.keys(p.tagOwners))
    if (!all.includes(t) && !inv.devices.some((d) => d.tags.includes(t))) add('warning', 'unused-tag', `${t} has owners but no rule or device uses it`, `tagOwners.${t}`)
  for (const d of inv.devices) for (const t of d.tags) if (!(t in p.tagOwners)) add('warning', 'device-tag-no-owner', `Device ${d.name} carries ${t}, which is missing from tagOwners`)

  // breadth
  for (const r of p.rules) {
    const anySrc = r.src.some((s) => s.sel === '*' || s.sel === 'autogroup:danger-all')
    for (const d of r.dst) {
      const allPorts = d.caps.some((c) => c.lo === 0 && c.hi === 65535)
      if (d.alias === '*' && allPorts) add(anySrc ? 'warning' : 'info', 'broad', anySrc ? `${r.path} allows anyone to reach everything on every port (*:*)` : `${r.path} lets ${r.src.map((s) => s.sel).join(', ')} reach every device and subnet on every port`, d.path)
      else if (anySrc && allPorts && d.alias !== 'autogroup:self') add('warning', 'broad', `${r.path} lets every device reach ${d.alias} on every port`, d.path)
    }
    for (const s of r.src) {
      if (s.sel === 'autogroup:danger-all') add('warning', 'danger-all', `${r.path} uses autogroup:danger-all, which includes sources outside your tailnet`, s.path)
      if (s.sel === 'autogroup:self') add('error', 'self-src', 'autogroup:self is only valid as a destination', s.path)
    }
  }

  // ssh sanity
  for (const r of p.ssh) {
    for (const d of r.dst) {
      if (d.sel === '*') add('error', 'ssh-dst', `SSH dst cannot be "*"; use tags, autogroup:self or groups`, d.path)
      else if ((d.sel.includes('@') && !d.sel.includes(':')) || ctx.addr(d.sel)) add('warning', 'ssh-dst', `SSH dst "${d.sel}": only your own devices (autogroup:self), tags, groups or autogroups are allowed`, d.path)
    }
    if (r.action === 'accept' && r.users.includes('root')) add('warning', 'ssh-root', `${r.path} accepts root logins without "check" re-authentication`, r.path)
    if (r.dst.some((d) => d.sel === 'autogroup:self') && r.src.some((s) => s.sel.startsWith('tag:') || s.sel === 'autogroup:tagged')) add('error', 'self-tagged', 'autogroup:self cannot be combined with tagged sources', r.path)
    if (inv.devices.length) {
      const pairs = inv.devices.flatMap((s) => inv.devices.filter((d) => d !== s && r.src.some((x) => ctx.srcMatch(x.sel, s)) && r.dst.some((x) => ctx.dstMatch(x.sel, s, { kind: 'device', dev: d }))).map((d) => [s, d] as const))
      if (pairs.length && !pairs.some(([s, d]) => capsAllow(capsBetween(ctx, s, { kind: 'device', dev: d }).caps, 'tcp', 22)))
        add('warning', 'ssh-no-network', `${r.path} can never connect: no acl/grant allows tcp:22 between its sources and destinations`, r.path)
    }
  }

  // auto approvers
  for (const d of inv.devices) {
    const fakeOwner = (sel: string) => ctx.srcMatch(sel, d)
    for (const route of d.routes) {
      if (route === '0.0.0.0/0' || route === '::/0') continue
      const rc = parseCidr(route)
      const ok = Object.entries(p.autoApprovers.routes).some(([c, os]) => {
        const cc = parseCidr(c)
        return cc && rc && rc.lo >= cc.lo && rc.hi <= cc.hi && os.some(fakeOwner)
      })
      if (!ok) add('info', 'route-not-auto', `${d.name} advertises ${route}, which needs manual approval (no matching autoApprovers.routes)`)
    }
    if (d.exitNode && !p.autoApprovers.exitNode.some(fakeOwner)) add('info', 'exit-not-auto', `${d.name} is an exit node but not covered by autoApprovers.exitNode`)
  }

  // dead + redundant rules (needs inventory)
  if (inv.devices.length && p.rules.length) {
    const targets = matrixTargets(p, inv)
    const contrib = p.rules.map((r) => inv.devices.map((s) => targets.map((t) => (t.kind === 'device' && t.dev === s ? [] : capsBetween(ctx, s, t, [r]).caps))))
    p.rules.forEach((r, ri) => {
      const cells = contrib[ri].flatMap((row, i) => row.map((c, j) => ({ c, i, j }))).filter((x) => x.c.length)
      if (!cells.length) {
        if (r.dst.some((d) => d.caps.length)) add('warning', 'dead-rule', `${r.path} matches no connection between devices in the inventory`, r.path)
        return
      }
      const coveredBy = new Set<string>()
      const redundant = cells.every(({ c, i, j }) => {
        const others = p.rules.flatMap((o, oi) => (oi === ri ? [] : contrib[oi][i][j]))
        p.rules.forEach((o, oi) => { if (oi !== ri && contrib[oi][i][j].length) coveredBy.add(o.path) })
        return subtractCaps(c, others).length === 0
      })
      if (redundant) add('warning', 'shadowed', `${r.path} is shadowed: everything it allows is already allowed by ${[...coveredBy].slice(0, 4).join(', ')}`, r.path)
    })
  }

  if (!p.tests.length && !p.sshTests.length) add('info', 'no-tests', 'No tests or sshTests: add assertions so future edits cannot silently change access')
  const rank = { error: 0, warning: 1, info: 2 }
  return out.sort((a, b) => rank[a.severity] - rank[b.severity])
}

// ---------- inventory helpers ----------

/** Build a plausible inventory from what the policy itself names. Everything here is a guess and is labelled as such in the UI. */
export function inferInventory(p: Policy): Inventory {
  const emails = new Set<string>()
  const scan = (s: string) => { if (s.includes('@') && !s.includes(':')) emails.add(s) }
  Object.values(p.groups).flat().forEach(scan)
  p.rules.forEach((r) => r.src.forEach((s) => scan(s.sel)))
  p.ssh.forEach((r) => r.src.forEach((s) => scan(s.sel)))
  p.tests.forEach((t) => scan(t.src))
  p.sshTests.forEach((t) => scan(t.src))
  Object.values(p.tagOwners).flat().forEach(scan)
  const sels = new Set([...p.rules.flatMap((r) => [...r.src.map((s) => s.sel), ...r.dst.map((d) => d.alias)]), ...p.ssh.flatMap((r) => [...r.src, ...r.dst].map((s) => s.sel)), ...Object.values(p.tagOwners).flat()])

  const users: User[] = [...emails].map((email) => ({ email, role: 'member' }))
  if (!users.length) users.push({ email: 'admin@example.com', role: 'member' })
  users[0].role = 'admin'
  for (const role of ROLES) if (role !== 'member' && role !== 'admin' && sels.has(`autogroup:${role}`)) users.push({ email: `${role}@example.com`, role })
  if (sels.has('autogroup:shared')) users.push({ email: 'guest@example.com', role: 'member', shared: true })

  // Address literals: tailnet IPs become devices, everything else is advertised by one subnet router.
  const literals = new Map<string, string>() // address -> name
  for (const [h, v] of Object.entries(p.hosts)) literals.set(v, h)
  for (const r of p.rules) for (const d of r.dst) if (parseCidr(d.alias) && !literals.has(d.alias)) literals.set(d.alias, d.alias)
  for (const c of Object.keys(p.autoApprovers.routes)) if (parseCidr(c) && !literals.has(c)) literals.set(c, c)
  const used = new Set<string>()
  const routes: string[] = []
  const devices: Device[] = []
  for (const [addr, name] of literals) {
    const r = parseCidr(addr)
    if (!r) continue
    // A single address used as a source (a LAN host behind a subnet router, say) needs a device to send from.
    const asSrc = p.rules.some((x) => x.src.some((y) => y.sel === name || y.sel === addr))
    if (r.lo === r.hi && (inTailnet(r) || asSrc)) { used.add(addr); devices.push({ name, ip: addr, owner: '', tags: [], routes: [] }) }
    else if (!inTailnet(r)) routes.push(r.lo === r.hi && !addr.includes('/') ? `${addr}/${addr.includes(':') ? 128 : 32}` : addr)
  }
  let n = 1
  const ip = () => {
    while (used.has(`100.64.0.${n}`)) n++
    used.add(`100.64.0.${n}`)
    return `100.64.0.${n++}`
  }
  const own: Device[] = users.map((u) => ({ name: `${u.email.split('@')[0]}-laptop`, ip: ip(), owner: u.email, tags: [], routes: [] }))
  own.push({ name: `${users[0].email.split('@')[0]}-phone`, ip: ip(), owner: users[0].email, tags: [], routes: [] })
  for (const t of Object.keys(p.tagOwners)) own.push({ name: `${t.slice(4)}-1`, ip: ip(), owner: p.tagOwners[t].find((o) => o.includes('@')) ?? '', tags: [t], routes: [] })
  devices.unshift(...own)
  const wantsExit = p.rules.some((r) => r.dst.some((d) => d.alias === 'autogroup:internet'))
  if (routes.length || wantsExit) devices.push({ name: 'subnet-router', ip: ip(), owner: '', tags: [], routes, exitNode: wantsExit })
  return { users, devices }
}

/** Parse `tailscale status --json` into an inventory. */
export function inventoryFromStatus(json: unknown): Inventory {
  const s = json as { Self?: StatusPeer; Peer?: Record<string, StatusPeer>; User?: Record<string, { LoginName?: string }> }
  if (!s || typeof s !== 'object' || !('Peer' in s || 'Self' in s)) throw new Error('Not `tailscale status --json` output (missing Self/Peer)')
  const userOf = (id?: number) => (id !== undefined ? s.User?.[String(id)]?.LoginName ?? '' : '')
  const peers = [s.Self, ...Object.values(s.Peer ?? {})].filter(Boolean) as StatusPeer[]
  const names = new Set<string>()
  const devices: Device[] = peers.map((p) => {
    const ips = p.TailscaleIPs ?? []
    const self = new Set(ips.flatMap((x) => [x, `${x}/32`, `${x}/128`]))
    // AllowedIPs carries every approved subnet route, including ones where this node is a standby, not the primary.
    const routes = [...new Set([...(p.PrimaryRoutes ?? []), ...(p.AllowedIPs ?? [])])].filter((r) => !self.has(r) && r !== '0.0.0.0/0' && r !== '::/0')
    const base = (p.DNSName?.split('.')[0] || p.HostName || 'device').toLowerCase()
    let name = base
    for (let i = 2; names.has(name); i++) name = `${base}-${i}`
    names.add(name)
    return { name, ip: ips.find((x) => x.includes('.')) ?? ips[0] ?? '', owner: p.Tags?.length ? '' : userOf(p.UserID), tags: p.Tags ?? [], routes, exitNode: !!p.ExitNodeOption }
  })
  const logins = Object.values(s.User ?? {}).map((u) => u.LoginName ?? '').filter((e) => e.includes('@'))
  const emails = [...new Set([...logins, ...devices.map((d) => d.owner).filter(Boolean)])]
  return { users: emails.map((email) => ({ email, role: 'member' })), devices }
}
interface StatusPeer { HostName?: string; DNSName?: string; TailscaleIPs?: string[] | null; AllowedIPs?: string[] | null; UserID?: number; Tags?: string[] | null; PrimaryRoutes?: string[] | null; ExitNodeOption?: boolean }

export const identityOf = (d: Device) => (d.tags.length ? [...d.tags].sort().join(' + ') : d.owner || d.name)

/** Coerce untrusted inventory (shared URL, localStorage) into a valid shape. */
export function sanitizeInventory(v: unknown): Inventory {
  const o = (v ?? {}) as { users?: unknown; devices?: unknown }
  const list = (x: unknown): Record<string, unknown>[] => (Array.isArray(x) ? x.filter((e) => e && typeof e === 'object') : [])
  const strList = (x: unknown) => (Array.isArray(x) ? x.filter((e): e is string => typeof e === 'string') : [])
  return {
    users: list(o.users).map((u) => ({ email: String(u.email ?? ''), role: (ROLES as unknown[]).includes(u.role) ? (u.role as Role) : 'member', shared: !!u.shared })),
    devices: list(o.devices).map((d) => ({ name: String(d.name ?? ''), ip: String(d.ip ?? ''), owner: String(d.owner ?? ''), tags: strList(d.tags), routes: strList(d.routes), exitNode: !!d.exitNode })),
  }
}
