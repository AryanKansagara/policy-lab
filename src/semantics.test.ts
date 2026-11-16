// Checks against Tailscale's published policy semantics and real policy files.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { assertionHolds, Ctx, explain, inferInventory, inventoryFromStatus, isPublic, lint, loadPolicy, parseCidr, runTests, type Device, type Inventory } from './engine.ts'
import { REAL_HOMELAB } from './realPolicy.ts'
import { SAMPLES } from './samples.ts'

const dev = (name: string, ip: string, owner: string, tags: string[] = [], routes: string[] = []): Device => ({ name, ip, owner, tags, routes })
const inv: Inventory = {
  users: [{ email: 'a@x.com', role: 'admin' }, { email: 'b@x.com', role: 'member' }],
  devices: [dev('a1', '100.64.0.1', 'a@x.com'), dev('b1', '100.64.0.3', 'b@x.com'), dev('srv', '100.64.0.10', '', ['tag:srv']), dev('rtr', '100.64.0.20', '', ['tag:rtr'], ['10.0.0.0/24', 'fd00:1::/64'])],
}
const load = (t: string) => {
  const l = loadPolicy(t)
  assert.ok(l.policy, l.parse.error?.message)
  return l.policy
}
const D = (n: string) => inv.devices.find((d) => d.name === n)!
const range = (s: string) => ({ kind: 'range' as const, label: s, ...parseCidr(s)! })
const testsOk = (policy: string) => runTests(load(policy), inv).map((r) => r.ok)

test('ICMP is allowed whenever any traffic is allowed between the pair (ACLs and bare grant ports)', () => {
  const acl = load('{"acls":[{"action":"accept","src":["a@x.com"],"dst":["tag:srv:22"]}]}')
  assert.equal(explain(new Ctx(acl, inv), D('a1'), { kind: 'device', dev: D('srv') }, 'icmp', 0).allowed, true)
  assert.equal(explain(new Ctx(acl, inv), D('b1'), { kind: 'device', dev: D('srv') }, 'icmp', 0).allowed, false)
  const grant = load('{"grants":[{"src":["a@x.com"],"dst":["tag:srv"],"ip":["443"]}]}')
  assert.equal(explain(new Ctx(grant, inv), D('a1'), { kind: 'device', dev: D('srv') }, 'icmp', 0).allowed, true)
})

test('tests without "proto" pass on TCP or UDP access, as documented', () => {
  const p = '{"acls":[{"action":"accept","src":["a@x.com"],"proto":"udp","dst":["tag:srv:53"]}],"tests":[{"src":"a@x.com","accept":["tag:srv:53"]},{"src":"a@x.com","proto":"tcp","deny":["tag:srv:53"]}]}'
  assert.deepEqual(testsOk(p), [true, true])
})

test('a group test source must hold for every member; sshTests reject groups', () => {
  const p = '{"groups":{"group:all":["a@x.com","b@x.com"]},"acls":[{"action":"accept","src":["a@x.com"],"dst":["tag:srv:443"]}],"tests":[{"src":"group:all","accept":["tag:srv:443"]},{"src":"group:all","deny":["tag:srv:443"]}],"sshTests":[{"src":"group:all","dst":["tag:srv"],"deny":["root"]}]}'
  const r = runTests(load(p), inv)
  assert.deepEqual(r.map((x) => x.ok), [false, false, false])
  assert.equal(r[0].assertions[0].actual, 'partial')
  assert.match(r[2].error ?? '', /not a group/)
})

test('tests cannot target a CIDR range', () => {
  const r = runTests(load('{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"tests":[{"src":"a@x.com","accept":["10.0.0.0/24:80"]}]}'), inv)
  assert.match(r[0].assertions[0].error ?? '', /CIDR/)
})

test('posture assertions: versions, IN, NOT IN, IS SET', () => {
  assert.equal(assertionHolds("node:tsVersion >= '1.104'", { 'node:tsVersion': '1.104.2' }), true)
  assert.equal(assertionHolds("node:tsVersion >= '1.104'", { 'node:tsVersion': '1.102.4' }), false)
  assert.equal(assertionHolds("node:tsVersion < '1.10'", { 'node:tsVersion': '1.9.8' }), true)
  assert.equal(assertionHolds("node:os IN ['macos', 'windows']", { 'node:os': 'windows' }), true)
  assert.equal(assertionHolds("node:os NOT IN ['macos', 'windows']", { 'node:os': 'windows' }), false)
  assert.equal(assertionHolds('custom:serial IS SET', {}), false)
  assert.equal(assertionHolds('custom:serial IS NOT SET', {}), true)
  assert.equal(assertionHolds("node:os == 'linux'", {}), false)
  const bad = loadPolicy('{"postures":{"posture:x":["node:os ~= linux"]}}').policy!
  assert.ok(bad.problems.some((p) => p.code === 'posture-syntax'))
})

test('srcPosture is enforced in tests and assumed (with a note) in Why?', () => {
  const p = `{"postures":{"posture:new":{"assertions":["node:tsVersion >= '1.80'"]}},
    "grants":[{"src":["a@x.com"],"dst":["tag:srv"],"ip":["tcp:443"],"srcPosture":["posture:new"]}],
    "tests":[{"src":"a@x.com","deny":["tag:srv:443"]},
             {"src":"a@x.com","srcPostureAttrs":{"node:tsVersion":"1.82.0"},"accept":["tag:srv:443"]},
             {"src":"a@x.com","srcPostureAttrs":{"node:tsVersion":"1.78.1"},"deny":["tag:srv:443"]}]}`
  assert.deepEqual(testsOk(p), [true, true, true])
  const e = explain(new Ctx(load(p), inv), D('a1'), { kind: 'device', dev: D('srv') }, 'tcp', 443)
  assert.equal(e.allowed, true)
  assert.ok(e.notes.some((n) => n.includes('posture:new')))
  // defaultSrcPosture applies to rules that name none
  assert.deepEqual(testsOk(`{"postures":{"posture:new":["node:tsVersion >= '1.80'"]},"defaultSrcPosture":["posture:new"],"acls":[{"action":"accept","src":["a@x.com"],"dst":["tag:srv:443"]}],"tests":[{"src":"a@x.com","deny":["tag:srv:443"]}]}`), [true])
})

test('IPv6 and IPv4 share one address space', () => {
  assert.deepEqual(parseCidr('::ffff:10.0.0.1'), parseCidr('10.0.0.1'))
  assert.deepEqual(parseCidr('fd00:1::/64')!.hi - parseCidr('fd00:1::/64')!.lo, (1n << 64n) - 1n)
  assert.equal(parseCidr('fd00::1/129'), null)
  assert.equal(parseCidr('1:2:3'), null)
  const p = load('{"ipsets":{"ipset:v6":["fd00:1::/64","remove fd00:1::/120"]},"grants":[{"src":["a@x.com"],"dst":["ipset:v6"],"ip":["tcp:80"]}]}')
  const ctx = new Ctx(p, inv)
  assert.equal(explain(ctx, D('a1'), range('fd00:1::1:5'), 'tcp', 80).allowed, true)
  assert.equal(explain(ctx, D('a1'), range('fd00:1::5'), 'tcp', 80).allowed, false)
})

test('autogroup:internet covers public addresses, not private ones', () => {
  assert.equal(isPublic(parseCidr('1.1.1.1')!), true)
  assert.equal(isPublic(parseCidr('2606:4700:4700::1111')!), true)
  assert.equal(isPublic(parseCidr('10.1.2.3')!), false)
  assert.equal(isPublic(parseCidr('fd7a:115c:a1e0::1')!), false)
  const p = '{"acls":[{"action":"accept","src":["a@x.com"],"dst":["autogroup:internet:*"]}],"tests":[{"src":"a@x.com","accept":["1.1.1.1:443","[2606:4700:4700::1111]:443"],"deny":["10.0.0.5:443"]}]}'
  assert.deepEqual(testsOk(p), [true])
})

test('Tailscale Services: svc: destinations are reached only when named', () => {
  const p = '{"grants":[{"src":["a@x.com"],"dst":["svc:grafana"],"ip":["tcp:443"]},{"src":["b@x.com"],"dst":["*"],"ip":["*"]}],"tests":[{"src":"a@x.com","accept":["svc:grafana:443"],"deny":["svc:grafana:22"]},{"src":"b@x.com","deny":["svc:grafana:443"]}]}'
  assert.deepEqual(testsOk(p), [true, true])
})

test('real public policy (mdlayher/homelab): every test block passes, on the sample and on an inferred inventory', () => {
  const p = load(REAL_HOMELAB)
  const sample = SAMPLES.find((s) => s.id === 'real-homelab')!
  for (const i of [sample.inventory, inferInventory(p)]) {
    const r = runTests(p, i)
    assert.equal(r.length, 19)
    assert.deepEqual(r.filter((x) => !x.ok).map((x) => x.path), [])
  }
  assert.deepEqual(lint(p, sample.inventory).filter((x) => x.severity === 'error'), [])
})

test('inference from a policy with no emails still gives every rule something to match', () => {
  // Shape of a small real homelab policy: autogroup:admin only, LAN IPs behind a subnet router.
  const p = load(`{"tagOwners":{"tag:k8s":["autogroup:admin"]},
    "acls":[{"action":"accept","src":["autogroup:member"],"dst":["192.168.1.201:80,443","192.168.1.200:6443"]},
            {"action":"accept","src":["autogroup:admin"],"dst":["tag:k8s:443"]},
            {"action":"accept","src":["autogroup:shared"],"dst":["tag:k8s:22"]}]}`)
  const i = inferInventory(p)
  assert.ok(i.devices.some((d) => d.routes.includes('192.168.1.201/32')))
  assert.deepEqual(lint(p, i).filter((x) => x.code === 'dead-rule'), [])
})

test('tailscale status --json: real field layout (nulls, IPv6, standby routes, tagged-devices, name clashes)', () => {
  // Field layout as printed by tailscale 1.7x/1.8x; addresses and names are made up.
  const status = {
    Version: '1.88.1-t1234567',
    BackendState: 'Running',
    TailscaleIPs: ['100.101.12.4', 'fd7a:115c:a1e0::6f01:c04'],
    Self: { ID: 'n1', HostName: 'work-mbp', DNSName: 'work-mbp.tail1a2b3.ts.net.', OS: 'macOS', UserID: 3101, TailscaleIPs: ['100.101.12.4', 'fd7a:115c:a1e0::6f01:c04'], AllowedIPs: ['100.101.12.4/32', 'fd7a:115c:a1e0::6f01:c04/128'], Tags: null, PrimaryRoutes: null, ExitNodeOption: false },
    Peer: {
      'nodekey:01': { HostName: 'router-b', DNSName: 'router-b.tail1a2b3.ts.net.', OS: 'linux', UserID: 9001, TailscaleIPs: ['100.101.12.9', 'fd7a:115c:a1e0::6f01:c09'], AllowedIPs: ['100.101.12.9/32', 'fd7a:115c:a1e0::6f01:c09/128', '10.20.0.0/16'], Tags: ['tag:router'], PrimaryRoutes: null, ExitNodeOption: true },
      'nodekey:02': { HostName: 'router-a', DNSName: 'router-a.tail1a2b3.ts.net.', OS: 'linux', UserID: 9001, TailscaleIPs: ['100.101.12.8'], AllowedIPs: ['100.101.12.8/32', '10.20.0.0/16', '0.0.0.0/0', '::/0'], Tags: ['tag:router'], PrimaryRoutes: ['10.20.0.0/16'], ExitNodeOption: true },
      'nodekey:03': { HostName: 'work-mbp', DNSName: 'work-mbp.other-tailnet.ts.net.', OS: 'macOS', UserID: 3102, TailscaleIPs: ['100.70.1.1'], AllowedIPs: ['100.70.1.1/32'], Tags: null, ShareeNode: true },
    },
    User: {
      '3101': { ID: 3101, LoginName: 'jane@corp.example', DisplayName: 'Jane', Roles: [] },
      '3102': { ID: 3102, LoginName: 'sam@partner.example', DisplayName: 'Sam', Roles: [] },
      '3103': { ID: 3103, LoginName: 'li@corp.example', DisplayName: 'Li', Roles: [] },
      '9001': { ID: 9001, LoginName: 'tagged-devices', DisplayName: 'tagged-devices', Roles: [] },
    },
  }
  const i = inventoryFromStatus(status)
  assert.deepEqual(i.devices.map((d) => [d.name, d.ip, d.owner, d.routes.join(), !!d.exitNode]), [
    ['work-mbp', '100.101.12.4', 'jane@corp.example', '', false],
    ['router-b', '100.101.12.9', '', '10.20.0.0/16', true],
    ['router-a', '100.101.12.8', '', '10.20.0.0/16', true],
    ['work-mbp-2', '100.70.1.1', 'sam@partner.example', '', false],
  ])
  assert.deepEqual(i.users.map((u) => u.email), ['jane@corp.example', 'sam@partner.example', 'li@corp.example'])
})
