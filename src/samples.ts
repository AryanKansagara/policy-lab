import type { Inventory } from './engine.ts'

export interface Sample { id: string; name: string; blurb: string; policy: string; previous: string; inventory: Inventory }

const startupPolicy = `// Acme Robotics: 14 people, one prod cluster, one staging, CI.
{
  "groups": {
    "group:eng": ["alice@acme.dev", "bob@acme.dev", "carol@acme.dev"],
    "group:sre": ["dana@acme.dev"],
    "group:sales": ["eve@acme.dev"],
    "group:interns": [], // nobody this quarter
  },

  "tagOwners": {
    "tag:prod":    ["group:sre"],
    "tag:staging": ["group:eng", "group:sre"],
    "tag:ci":      ["group:sre"],
    "tag:monitoring": ["group:sre"],
  },

  "hosts": {
    "metrics": "100.64.0.20",
    "office-lan": "192.168.10.0/24",
  },

  "acls": [
    // SREs can reach everything.
    {"action": "accept", "src": ["group:sre"], "dst": ["*:*"]},

    // Engineers: staging fully, prod only over HTTPS.
    {"action": "accept", "src": ["group:eng"], "dst": ["tag:staging:*", "tag:prod:443"]},

    // CI deploys to staging and prod.
    {"action": "accept", "src": ["tag:ci"], "dst": ["tag:staging:22,443", "tag:prod:22"]},

    // Everyone can see dashboards and print in the office.
    {"action": "accept", "src": ["autogroup:member"], "dst": ["metrics:3000", "office-lan:631"]},

    // Leftover from the migration; already covered by the rule above.
    {"action": "accept", "src": ["group:eng"], "dst": ["metrics:3000"]},

    // Prometheus scrapes node exporters everywhere.
    {"action": "accept", "src": ["tag:monitoring"], "dst": ["tag:prod:9100", "tag:staging:9100"]},

    // Your own devices can talk to each other.
    {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]},
  ],

  "ssh": [
    {"action": "check", "src": ["group:sre"], "dst": ["tag:prod"], "users": ["root", "ubuntu"], "checkPeriod": "12h"},
    {"action": "accept", "src": ["group:eng"], "dst": ["tag:staging"], "users": ["ubuntu"]},
    {"action": "accept", "src": ["tag:ci"], "dst": ["tag:prod", "tag:staging"], "users": ["deploy"]},
    {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot"]},
  ],

  "tests": [
    {"src": "alice@acme.dev", "accept": ["tag:prod:443", "tag:staging:22"], "deny": ["tag:prod:22"]},
    {"src": "eve@acme.dev", "accept": ["metrics:3000"], "deny": ["tag:staging:443", "tag:prod:443"]},
    {"src": "tag:ci", "accept": ["tag:prod:22"], "deny": ["tag:prod:5432"]},
    // Sales should not reach the office printer subnet? (this one fails on purpose)
    {"src": "eve@acme.dev", "deny": ["192.168.10.5:631"]},
  ],

  "sshTests": [
    {"src": "dana@acme.dev", "dst": ["tag:prod"], "check": ["root", "ubuntu"]},
    {"src": "bob@acme.dev", "dst": ["tag:staging"], "accept": ["ubuntu"], "deny": ["root"]},
    {"src": "bob@acme.dev", "dst": ["tag:prod"], "deny": ["ubuntu"]},
  ],

  "autoApprovers": {
    "routes": {"192.168.10.0/24": ["group:sre"]},
  },
}
`

const startupPrevious = startupPolicy
  .replace(`"dst": ["tag:staging:22,443", "tag:prod:22"]`, `"dst": ["tag:staging:22,443", "tag:prod:22,443"]`)
  .replace(`"dst": ["tag:staging:*", "tag:prod:443"]`, `"dst": ["tag:staging:*"]`)
  .replace(`{"action": "accept", "src": ["autogroup:member"], "dst": ["metrics:3000", "office-lan:631"]},`, `{"action": "accept", "src": ["autogroup:member"], "dst": ["metrics:3000"]},`)

const startupInv: Inventory = {
  users: [
    { email: 'dana@acme.dev', role: 'owner' },
    { email: 'alice@acme.dev', role: 'admin' },
    { email: 'bob@acme.dev', role: 'member' },
    { email: 'carol@acme.dev', role: 'member' },
    { email: 'eve@acme.dev', role: 'member' },
  ],
  devices: [
    { name: 'dana-mbp', ip: '100.64.0.2', owner: 'dana@acme.dev', tags: [], routes: [] },
    { name: 'alice-mbp', ip: '100.64.0.3', owner: 'alice@acme.dev', tags: [], routes: [] },
    { name: 'alice-pixel', ip: '100.64.0.4', owner: 'alice@acme.dev', tags: [], routes: [] },
    { name: 'bob-thinkpad', ip: '100.64.0.5', owner: 'bob@acme.dev', tags: [], routes: [] },
    { name: 'carol-mbp', ip: '100.64.0.6', owner: 'carol@acme.dev', tags: [], routes: [] },
    { name: 'eve-ipad', ip: '100.64.0.7', owner: 'eve@acme.dev', tags: [], routes: [] },
    { name: 'api-prod-1', ip: '100.64.0.10', owner: 'dana@acme.dev', tags: ['tag:prod'], routes: [] },
    { name: 'db-prod-1', ip: '100.64.0.11', owner: 'dana@acme.dev', tags: ['tag:prod'], routes: [] },
    { name: 'staging-1', ip: '100.64.0.12', owner: 'bob@acme.dev', tags: ['tag:staging'], routes: [] },
    { name: 'gh-runner', ip: '100.64.0.13', owner: 'dana@acme.dev', tags: ['tag:ci'], routes: [] },
    { name: 'grafana', ip: '100.64.0.20', owner: 'dana@acme.dev', tags: ['tag:monitoring'], routes: [] },
    { name: 'office-router', ip: '100.64.0.30', owner: 'dana@acme.dev', tags: [], routes: ['192.168.10.0/24'] },
  ],
}

const homelabPolicy = `// The Nguyen household: a NAS, a Home Assistant box, an exit node.
{
  "groups": {
    "group:family": ["minh@gmail.com", "lan@gmail.com", "kids@gmail.com"],
    "group:admins": ["minh@gmail.com"],
  },
  "tagOwners": {
    "tag:server": ["group:admins"],
    "tag:nas": ["group:admins"],
    "tag:exit": ["group:admins"],
    "tag:iot": ["group:admins"],
  },
  "hosts": {
    "home-lan": "192.168.1.0/24",
    "camera": "192.168.1.40",
  },
  "grants": [
    // Admin gets everything (flagged by the linter, intentionally).
    {"src": ["group:admins"], "dst": ["*"], "ip": ["*"]},

    // Family: Plex + SMB on the NAS, Home Assistant UI, and the exit node.
    {"src": ["group:family"], "dst": ["tag:nas"], "ip": ["tcp:32400", "tcp:445"]},
    {"src": ["group:family"], "dst": ["tag:server"], "ip": ["tcp:8123"]},
    {"src": ["group:family"], "dst": ["autogroup:internet"], "ip": ["*"]},

    // Home Assistant talks to IoT gear on the LAN, but not the camera.
    {"src": ["tag:server"], "dst": ["home-lan"], "ip": ["tcp:80", "tcp:443", "udp:5353"]},

    // Everyone reaches their own devices.
    {"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["*"]},
  ],
  "ssh": [
    {"action": "accept", "src": ["group:admins"], "dst": ["tag:server", "tag:nas"], "users": ["root", "minh"]},
    {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot"]},
  ],
  "tests": [
    {"src": "kids@gmail.com", "accept": ["tag:nas:32400"], "deny": ["tag:nas:22", "camera:554"]},
    {"src": "lan@gmail.com", "accept": ["tag:server:8123"], "deny": ["tag:server:22"]},
  ],
  "sshTests": [
    {"src": "kids@gmail.com", "dst": ["tag:nas"], "deny": ["root", "kids"]},
  ],
  "autoApprovers": {
    "routes": {"192.168.1.0/24": ["tag:server"]},
    "exitNode": ["tag:exit"],
  },
}
`
const homelabPrevious = homelabPolicy.replace(`"ip": ["tcp:32400", "tcp:445"]`, `"ip": ["tcp:32400"]`).replace(`{"src": ["group:family"], "dst": ["autogroup:internet"], "ip": ["*"]},\n`, '')

const homelabInv: Inventory = {
  users: [
    { email: 'minh@gmail.com', role: 'owner' },
    { email: 'lan@gmail.com', role: 'member' },
    { email: 'kids@gmail.com', role: 'member' },
    { email: 'grandma@yahoo.com', role: 'member', shared: true },
  ],
  devices: [
    { name: 'minh-laptop', ip: '100.101.1.1', owner: 'minh@gmail.com', tags: [], routes: [] },
    { name: 'minh-phone', ip: '100.101.1.2', owner: 'minh@gmail.com', tags: [], routes: [] },
    { name: 'lan-phone', ip: '100.101.1.3', owner: 'lan@gmail.com', tags: [], routes: [] },
    { name: 'kids-ipad', ip: '100.101.1.4', owner: 'kids@gmail.com', tags: [], routes: [] },
    { name: 'grandma-tablet', ip: '100.101.1.5', owner: 'grandma@yahoo.com', tags: [], routes: [] },
    { name: 'synology', ip: '100.101.2.1', owner: 'minh@gmail.com', tags: ['tag:nas'], routes: [] },
    { name: 'homeassistant', ip: '100.101.2.2', owner: 'minh@gmail.com', tags: ['tag:server'], routes: ['192.168.1.0/24'] },
    { name: 'pi-exit', ip: '100.101.2.3', owner: 'minh@gmail.com', tags: ['tag:exit'], routes: [], exitNode: true },
  ],
}

const enterprisePolicy = `// Globex: grants-first policy with app capabilities, ipsets, posture and via.
{
  "groups": {
    "group:platform": ["priya@globex.com", "omar@globex.com"],
    "group:data": ["li@globex.com", "sam@globex.com"],
    "group:support": ["jo@globex.com"],
    "group:contractors": ["vendor@outsourcer.io"],
    "group:security": ["kim@globex.com"],
  },
  "tagOwners": {
    "tag:k8s": ["group:platform"],
    "tag:db": ["group:platform"],
    "tag:tailsql": ["group:data"],
    "tag:router-us": ["group:platform"],
    "tag:bastion": ["group:security"],
    "tag:legacy": ["group:platform"],
  },
  "ipsets": {
    "ipset:vpc-us": ["10.10.0.0/16", "remove 10.10.99.0/24"],
    "ipset:pci": ["10.10.99.0/24"],
  },
  "postures": {
    "posture:managed": ["node:os IN ['macos', 'windows']", "node:tsReleaseTrack == 'stable'"],
  },
  "grants": [
    // Platform runs the clusters.
    {"src": ["group:platform"], "dst": ["tag:k8s", "tag:db"], "ip": ["tcp:443", "tcp:6443", "tcp:5432"]},

    // Data team: TailSQL with read-only access to the warehouse.
    {
      "src": ["group:data"],
      "dst": ["tag:tailsql"],
      "ip": ["tcp:443"],
      "app": {"tailscale.com/cap/tailsql": [{"dataSrc": ["warehouse"]}]},
    },
    {"src": ["group:data"], "dst": ["tag:db"], "ip": ["tcp:5432"], "srcPosture": ["posture:managed"]},

    // VPC subnets via the US router only.
    {"src": ["group:platform", "group:data"], "dst": ["ipset:vpc-us"], "ip": ["tcp:443", "tcp:5432"], "via": ["tag:router-us"]},

    // PCI segment: security team only, through the bastion.
    {"src": ["group:security"], "dst": ["tag:bastion"], "ip": ["tcp:22"]},
    {"src": ["tag:bastion"], "dst": ["ipset:pci"], "ip": ["tcp:22", "tcp:443"]},

    // Support reads dashboards on k8s.
    {"src": ["group:support"], "dst": ["tag:k8s"], "ip": ["tcp:443"]},

    // Contractors: one legacy box, but on every port and protocol.
    {"src": ["group:contractors"], "dst": ["tag:legacy"], "ip": ["*"]},

    // Kubernetes nodes talk to Postgres.
    {"src": ["tag:k8s"], "dst": ["tag:db"], "ip": ["tcp:5432"]},
  ],
  "acls": [
    // Legacy rule kept during the grants migration (now redundant).
    {"action": "accept", "src": ["group:platform"], "proto": "tcp", "dst": ["tag:k8s:443"]},
  ],
  "ssh": [
    {"action": "check", "src": ["group:platform"], "dst": ["tag:k8s", "tag:db"], "users": ["ubuntu", "root"], "checkPeriod": "4h"},
    {"action": "accept", "src": ["group:security"], "dst": ["tag:bastion"], "users": ["autogroup:nonroot"]},
  ],
  "tests": [
    {"src": "li@globex.com", "accept": ["tag:tailsql:443", "tag:db:5432", "10.10.4.20:5432"], "deny": ["tag:k8s:6443", "10.10.99.5:443"]},
    {"src": "vendor@outsourcer.io", "deny": ["tag:db:5432", "tag:k8s:443"]},
    {"src": "jo@globex.com", "accept": ["tag:k8s:443"], "deny": ["tag:db:5432"]},
    {"src": "tag:bastion", "accept": ["10.10.99.5:22"]},
  ],
  "sshTests": [
    {"src": "priya@globex.com", "dst": ["tag:db"], "check": ["root", "ubuntu"]},
    {"src": "li@globex.com", "dst": ["tag:db"], "deny": ["ubuntu"]},
  ],
  "autoApprovers": {
    "routes": {"10.10.0.0/16": ["tag:router-us"]},
  },
}
`
const enterprisePrevious = enterprisePolicy
  .replace(`{"src": ["group:contractors"], "dst": ["tag:legacy"], "ip": ["*"]},`, `{"src": ["group:contractors"], "dst": ["tag:legacy"], "ip": ["tcp:443"]},`)
  .replace(`"ip": ["tcp:443", "tcp:6443", "tcp:5432"]`, `"ip": ["tcp:443", "tcp:6443"]`)

const enterpriseInv: Inventory = {
  users: [
    { email: 'priya@globex.com', role: 'admin' },
    { email: 'omar@globex.com', role: 'network-admin' },
    { email: 'li@globex.com', role: 'member' },
    { email: 'sam@globex.com', role: 'member' },
    { email: 'jo@globex.com', role: 'member' },
    { email: 'kim@globex.com', role: 'it-admin' },
    { email: 'vendor@outsourcer.io', role: 'member' },
  ],
  devices: [
    { name: 'priya-mbp', ip: '100.80.0.1', owner: 'priya@globex.com', tags: [], routes: [] },
    { name: 'omar-mbp', ip: '100.80.0.2', owner: 'omar@globex.com', tags: [], routes: [] },
    { name: 'li-mbp', ip: '100.80.0.3', owner: 'li@globex.com', tags: [], routes: [] },
    { name: 'sam-xps', ip: '100.80.0.4', owner: 'sam@globex.com', tags: [], routes: [] },
    { name: 'jo-mbp', ip: '100.80.0.5', owner: 'jo@globex.com', tags: [], routes: [] },
    { name: 'kim-mbp', ip: '100.80.0.6', owner: 'kim@globex.com', tags: [], routes: [] },
    { name: 'vendor-win', ip: '100.80.0.7', owner: 'vendor@outsourcer.io', tags: [], routes: [] },
    { name: 'k8s-node-a', ip: '100.80.1.1', owner: '', tags: ['tag:k8s'], routes: [] },
    { name: 'k8s-node-b', ip: '100.80.1.2', owner: '', tags: ['tag:k8s'], routes: [] },
    { name: 'pg-primary', ip: '100.80.1.10', owner: '', tags: ['tag:db'], routes: [] },
    { name: 'tailsql', ip: '100.80.1.20', owner: '', tags: ['tag:tailsql'], routes: [] },
    { name: 'bastion', ip: '100.80.1.30', owner: '', tags: ['tag:bastion'], routes: [] },
    { name: 'legacy-erp', ip: '100.80.1.40', owner: '', tags: ['tag:legacy'], routes: [] },
    { name: 'router-us', ip: '100.80.2.1', owner: '', tags: ['tag:router-us'], routes: ['10.10.0.0/16'] },
  ],
}

export const SAMPLES: Sample[] = [
  { id: 'startup', name: 'Startup (ACLs)', blurb: 'Groups, tags, hosts, SSH check mode and a deliberately failing test.', policy: startupPolicy, previous: startupPrevious, inventory: startupInv },
  { id: 'homelab', name: 'Homelab (grants)', blurb: 'Family tailnet with a NAS, subnet router, exit node and autogroup:self.', policy: homelabPolicy, previous: homelabPrevious, inventory: homelabInv },
  { id: 'enterprise', name: 'Enterprise (grants + app caps)', blurb: 'ipsets, srcPosture, via routing, TailSQL capabilities, ACL→grants migration.', policy: enterprisePolicy, previous: enterprisePrevious, inventory: enterpriseInv },
]
