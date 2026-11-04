import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseHuJSON } from './hujson.ts'
import { Ctx, capsAllow, computeMatrix, diffPolicies, explain, formatCaps, inferInventory, inventoryFromStatus, lint, loadPolicy, parseIpCap, runTests, sanitizeInventory, sshEval, subtractCaps, type Device, type Inventory } from './engine.ts'
import { SAMPLES } from './samples.ts'
import { buildGraph, seedLayout, stepLayout } from './graph.ts'
import { decodeState, encodeState } from './share.ts'

const dev = (name: string, ip: string, owner: string, tags: string[] = [], routes: string[] = []): Device => ({ name, ip, owner, tags, routes })
const inv: Inventory = {
  users: [{ email: 'a@x.com', role: 'admin' }, { email: 'b@x.com', role: 'member' }, { email: 's@y.com', role: 'member', shared: true }],
  devices: [dev('a1', '100.64.0.1', 'a@x.com'), dev('a2', '100.64.0.2', 'a@x.com'), dev('b1', '100.64.0.3', 'b@x.com'), dev('srv', '100.64.0.10', 'a@x.com', ['tag:srv']), dev('s1', '100.64.0.5', 's@y.com'), dev('rtr', '100.64.0.20', '', ['tag:rtr'], ['10.0.0.0/24'])],
}
const load = (t: string) => {
  const l = loadPolicy(t)
  assert.ok(l.policy, l.parse.error?.message)
  return l.policy
}
const D = (name: string) => inv.devices.find((d) => d.name === name)!
const allowed = (policy: string, src: string, dst: string, port: number, proto = 'tcp') => {
  const p = load(policy)
  return explain(new Ctx(p, inv), D(src), { kind: 'device', dev: D(dst) }, proto, port).allowed
}

test('hujson: comments and trailing commas parse, spans point at values', () => {
  const text = '{\n  // c\n  "a": [1, 2,], /* b */\n  "b": {"c": "d",},\n}'
  const r = parseHuJSON(text)
  assert.deepEqual(r.value, { a: [1, 2], b: { c: 'd' } })
  const s = r.spans.get('a.1')!
  assert.equal(text.slice(s.start, s.end), '2')
})

test('hujson: error has precise line/col', () => {
  const r = parseHuJSON('{\n  "a": 1\n  "b": 2\n}')
  assert.equal(r.error?.line, 3)
  assert.equal(r.error?.col, 3)
  assert.match(r.error!.message, /missing comma/)
})

test('hujson: duplicate keys are reported', () => {
  const l = loadPolicy('{"groups": {"group:a": []}, "groups": {}}')
  assert.ok(l.policy!.problems.some((p) => p.code === 'duplicate-key'))
})

test('acl: groups + tag + ports', () => {
  const p = '{"groups":{"group:eng":["b@x.com"]},"tagOwners":{"tag:srv":[]},"acls":[{"action":"accept","src":["group:eng"],"dst":["tag:srv:22,443"]}]}'
  assert.equal(allowed(p, 'b1', 'srv', 443), true)
  assert.equal(allowed(p, 'b1', 'srv', 80), false)
  assert.equal(allowed(p, 'a1', 'srv', 443), false)
})

test('acl: proto restricts, no proto means tcp+udp', () => {
  assert.equal(allowed('{"acls":[{"action":"accept","src":["*"],"proto":"udp","dst":["*:53"]}]}', 'a1', 'b1', 53, 'tcp'), false)
  assert.equal(allowed('{"acls":[{"action":"accept","src":["*"],"proto":"udp","dst":["*:53"]}]}', 'a1', 'b1', 53, 'udp'), true)
  assert.equal(allowed('{"acls":[{"action":"accept","src":["*"],"dst":["*:53"]}]}', 'a1', 'b1', 53, 'udp'), true)
})

test('autogroup:self only reaches own untagged devices', () => {
  const p = '{"acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}]}'
  assert.equal(allowed(p, 'a1', 'a2', 22), true)
  assert.equal(allowed(p, 'a1', 'b1', 22), false)
  assert.equal(allowed(p, 'a1', 'srv', 22), false) // tagged device is not "self"
})

test('autogroup:member excludes shared users; tagged devices lose user identity', () => {
  const p = '{"acls":[{"action":"accept","src":["autogroup:member"],"dst":["b1:*"]}],"hosts":{"b1":"100.64.0.3"}}'
  assert.equal(allowed(p, 'a1', 'b1', 80), true)
  assert.equal(allowed(p, 's1', 'b1', 80), false)
  assert.equal(allowed(p, 'srv', 'b1', 80), false)
  assert.equal(allowed('{"acls":[{"action":"accept","src":["a@x.com"],"dst":["*:*"]}]}', 'srv', 'b1', 80), false)
})

test('grants: ip caps, app-only grants carry no network access', () => {
  assert.deepEqual(parseIpCap('tcp:80,443'), [{ proto: 'tcp', lo: 80, hi: 80 }, { proto: 'tcp', lo: 443, hi: 443 }])
  assert.equal(parseIpCap('tcp:abc'), null)
  const p = '{"grants":[{"src":["autogroup:admin"],"dst":["tag:srv"],"ip":["udp:53","tcp:8000-8100"]},{"src":["*"],"dst":["*"],"app":{"example.com/cap/x":[{}]}}],"tagOwners":{"tag:srv":[]}}'
  assert.equal(allowed(p, 'a1', 'srv', 8050), true)
  assert.equal(allowed(p, 'a1', 'srv', 53, 'udp'), true)
  assert.equal(allowed(p, 'b1', 'srv', 8050), false)
})

test('subnet routes, hosts and ipsets with remove', () => {
  const p = load('{"ipsets":{"ipset:lan":["10.0.0.0/24","remove 10.0.0.128/25"]},"grants":[{"src":["b@x.com"],"dst":["ipset:lan"],"ip":["tcp:80"]}]}')
  const ctx = new Ctx(p, inv)
  const ip = (s: string) => ({ kind: 'range' as const, label: s, ...(() => { const [a, b, c, d] = s.split('.').map(Number); const n = a * 2 ** 24 + b * 65536 + c * 256 + d; return { lo: n, hi: n } })() })
  assert.equal(explain(ctx, D('b1'), ip('10.0.0.5'), 'tcp', 80).allowed, true)
  assert.equal(explain(ctx, D('b1'), ip('10.0.0.200'), 'tcp', 80).allowed, false)
})

test('why: near misses explain port mismatch', () => {
  const p = load('{"acls":[{"action":"accept","src":["b@x.com"],"dst":["a1:443"]}],"hosts":{"a1":"100.64.0.1"}}')
  const e = explain(new Ctx(p, inv), D('b1'), { kind: 'device', dev: D('a1') }, 'tcp', 22)
  assert.equal(e.allowed, false)
  assert.match(e.near[0].reason, /only allows tcp\+udp:443/)
})

test('ssh: first matching rule wins; nonroot; port 22 requirement surfaced', () => {
  const p = load(`{"tagOwners":{"tag:srv":[]},"ssh":[
    {"action":"check","src":["autogroup:admin"],"dst":["tag:srv"],"users":["root"]},
    {"action":"accept","src":["autogroup:member"],"dst":["tag:srv"],"users":["autogroup:nonroot"]}],
    "acls":[{"action":"accept","src":["autogroup:admin"],"dst":["tag:srv:22"]}]}`)
  const ctx = new Ctx(p, inv)
  assert.equal(sshEval(ctx, D('a1'), D('srv'), 'root').action, 'check')
  assert.equal(sshEval(ctx, D('b1'), D('srv'), 'root').action, 'deny')
  const r = sshEval(ctx, D('b1'), D('srv'), 'ubuntu')
  assert.equal(r.action, 'accept')
  assert.equal(r.network22, false)
})

test('tests + sshTests run against samples (startup has one intentional failure)', () => {
  const s = SAMPLES[0]
  const res = runTests(load(s.policy), s.inventory)
  const failing = res.filter((r) => !r.ok)
  assert.equal(failing.length, 1)
  assert.equal(failing[0].path, 'tests.3')
  for (const other of SAMPLES.slice(1)) assert.ok(runTests(load(other.policy), other.inventory).every((r) => r.ok), other.id)
})

test('diff: gained and lost connections', () => {
  const a = load('{"acls":[{"action":"accept","src":["b@x.com"],"dst":["a1:22,443"]}],"hosts":{"a1":"100.64.0.1"}}')
  const b = load('{"acls":[{"action":"accept","src":["b@x.com"],"dst":["a1:443,8080"]}],"hosts":{"a1":"100.64.0.1"}}')
  const rows = diffPolicies(a, b, inv)
  assert.equal(rows.length, 1)
  assert.equal(formatCaps(rows[0].gained), 'tcp+udp:8080')
  assert.equal(formatCaps(rows[0].lost), 'tcp+udp:22')
})

test('caps subtraction and merge', () => {
  assert.deepEqual(subtractCaps([{ proto: 'tcp', lo: 1, hi: 100 }], [{ proto: 'tcp', lo: 10, hi: 20 }]), [{ proto: 'tcp', lo: 1, hi: 9 }, { proto: 'tcp', lo: 21, hi: 100 }])
  assert.deepEqual(subtractCaps([{ proto: 'udp', lo: 53, hi: 53 }], [{ proto: '*', lo: 0, hi: 65535 }]), [])
  assert.equal(capsAllow([{ proto: '*', lo: 0, hi: 65535 }], 'icmp', 0), true)
})

test('lints: unused group, tag without owner, broad, shadowed, undefined group', () => {
  const p = load(`{"groups":{"group:unused":[],"group:eng":["b@x.com"]},
    "acls":[{"action":"accept","src":["*"],"dst":["*:*"]},{"action":"accept","src":["group:eng"],"dst":["tag:srv:22"]},
            {"action":"accept","src":["group:ghost"],"dst":["a1:22"]}],"hosts":{"a1":"100.64.0.1"}}`)
  const codes = lint(p, inv).map((x) => x.code)
  for (const c of ['unused-group', 'tag-no-owner', 'broad', 'shadowed', 'undefined-group', 'device-tag-no-owner']) assert.ok(codes.includes(c), c)
})

test('matrix: every sample computes and the startup sample has the redundant metrics rule', () => {
  for (const s of SAMPLES) {
    const p = load(s.policy)
    const m = computeMatrix(p, s.inventory)
    assert.equal(m.cells.length, s.inventory.devices.length)
  }
  const s = SAMPLES[0]
  assert.ok(lint(load(s.policy), s.inventory).some((x) => x.code === 'shadowed' && x.path === 'acls.4'))
})

test('acl dst without a port is an error', () => {
  const l = loadPolicy('{"acls":[{"action":"accept","src":["*"],"dst":["tag:prod"]}]}')
  assert.ok(l.policy!.problems.some((p) => p.code === 'dst-port'))
})

test('inventory from tailscale status --json and inference from policy', () => {
  const inv2 = inventoryFromStatus({
    Self: { HostName: 'Me', DNSName: 'me.tail.ts.net.', TailscaleIPs: ['100.1.1.1', 'fd7a::1'], UserID: 1 },
    Peer: { k: { HostName: 'db', DNSName: 'db.tail.ts.net.', TailscaleIPs: ['100.1.1.2'], UserID: 1, Tags: ['tag:db'], PrimaryRoutes: ['10.0.0.0/24'] } },
    User: { '1': { LoginName: 'me@x.com' } },
  })
  assert.deepEqual(inv2.devices.map((d) => [d.name, d.ip, d.owner, d.tags.join()]), [['me', '100.1.1.1', 'me@x.com', ''], ['db', '100.1.1.2', '', 'tag:db']])
  assert.throws(() => inventoryFromStatus({ foo: 1 }))
  const inferred = inferInventory(load(SAMPLES[0].policy))
  assert.ok(inferred.devices.some((d) => d.tags.includes('tag:prod')))
  assert.ok(inferred.users.some((u) => u.email === 'alice@acme.dev'))
})

test('graph: identities merge devices, edges carry caps and rule paths', () => {
  const s = SAMPLES[0]
  const g = buildGraph(load(s.policy), s.inventory)
  const alice = g.nodes.find((n) => n.id === 'alice@acme.dev')!
  assert.equal(alice.devices.length, 2)
  const e = g.edges.find((x) => x.from === 'alice@acme.dev' && x.to === 'tag:prod')!
  assert.equal(formatCaps(e.caps), 'tcp+udp:443')
  assert.ok(e.rules.includes('acls.1'))
  assert.ok(g.nodes.some((n) => n.kind === 'subnet'))
  assert.ok(!g.edges.some((x) => x.from === 'eve@acme.dev' && x.to === 'tag:prod'))
})

test('force layout stays finite and inside bounds', () => {
  const s = SAMPLES[2]
  const g = buildGraph(load(s.policy), s.inventory)
  seedLayout(g, 800, 500)
  for (let i = 0; i < 300; i++) stepLayout(g, 800, 500, 1 - i / 300)
  for (const n of g.nodes) {
    assert.ok(Number.isFinite(n.x) && n.x >= 0 && n.x <= 800)
    assert.ok(Number.isFinite(n.y) && n.y >= 0 && n.y <= 500)
  }
  const [a, b] = g.nodes
  assert.ok(Math.hypot(a.x - b.x, a.y - b.y) > 5)
})

test('share: state round-trips through the URL codec', async () => {
  const state = { t: SAMPLES[2].policy, i: SAMPLES[2].inventory }
  const code = await encodeState(state)
  assert.match(code, /^[A-Za-z0-9_-]+$/)
  assert.ok(code.length < state.t.length)
  assert.deepEqual(await decodeState(code), state)
})

test('sanitizeInventory coerces untrusted input', () => {
  const clean = sanitizeInventory({ users: [{ email: 'a@b', role: 'root' }, 3], devices: [{ name: 1, tags: ['tag:a', 2], routes: 'x' }] })
  assert.deepEqual(clean.users, [{ email: 'a@b', role: 'member', shared: false }])
  assert.deepEqual(clean.devices[0], { name: '1', ip: '', owner: '', tags: ['tag:a'], routes: [], exitNode: false })
  assert.deepEqual(sanitizeInventory(null), { users: [], devices: [] })
})

test('sample baselines show a blast radius in both directions', () => {
  const s = SAMPLES[0]
  const rows = diffPolicies(load(s.previous), load(s.policy), s.inventory)
  assert.ok(rows.some((r) => r.gained.length))
  const lost = rows.find((r) => r.src === 'gh-runner' && r.dst === 'api-prod-1')!
  assert.equal(formatCaps(lost.lost), 'tcp+udp:443')
})
