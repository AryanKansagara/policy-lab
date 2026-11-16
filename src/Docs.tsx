import { Brand, Footer, Link, ThemeToggle } from './ui.tsx'

const RULES: [string, string, string][] = [
  ['ACL without "proto"', 'Applies to TCP and UDP.', 'https://tailscale.com/kb/1337/policy-syntax'],
  ['ICMP', 'Allowed between two addresses whenever any other traffic is allowed between them, so ping follows any port rule.', 'https://tailscale.com/kb/1337/policy-syntax'],
  ['Grant "ip": bare port or "*"', 'Implies TCP, UDP and ICMP.', 'https://tailscale.com/kb/1538/grants-syntax'],
  ['tests without "proto"', 'Pass when either TCP or UDP reaches the port.', 'https://tailscale.com/kb/1337/policy-syntax'],
  ['tests "src"', 'A user, group, tag or host. A group must hold for every member.', 'https://tailscale.com/kb/1337/policy-syntax'],
  ['tests destinations', 'host:port with one numeric port. CIDR ranges are rejected.', 'https://tailscale.com/kb/1337/policy-syntax'],
  ['sshTests "src"', 'A user or tag. Groups are rejected, matching tailscale/tailscale#11790.', 'https://github.com/tailscale/tailscale/issues/11790'],
  ['srcPosture', 'A rule applies when the device meets every assertion of any one listed posture. defaultSrcPosture covers rules that name none. Tests use srcPostureAttrs, or no attributes when it is missing.', 'https://tailscale.com/docs/features/device-posture/postures-in-access-rules'],
  ['autogroup:internet', 'Public addresses only. Private, CGNAT, link-local, loopback and multicast ranges are excluded.', 'https://tailscale.com/kb/1337/policy-syntax'],
  ['svc: destinations', 'A Tailscale Service is reached only by a grant that names it. "*" does not cover services.', 'https://tailscale.com/kb/1538/grants-syntax'],
]

export default function Docs() {
  return (
    <div className="landing">
      <header className="topbar landing-bar">
        <Brand />
        <nav className="topbar-actions" aria-label="Main">
          <ThemeToggle />
          <Link href="/app" className="btn primary">Open the lab</Link>
        </nav>
      </header>
      <main className="docs">
        <p className="mono-label eyebrow">Docs</p>
        <h1>How Policy Lab evaluates a tailnet policy</h1>

        <h2>Inputs</h2>
        <ul>
          <li><strong>Policy file</strong>: HuJSON, the format of the admin console's Access controls editor and of <code>policy.hujson</code> in GitOps repos. Comments and trailing commas are fine.</li>
          <li><strong>Inventory</strong>: paste the output of <code>tailscale status --json</code> from any device. Each device keeps its first IPv4 address, tags, approved subnet routes (from <code>PrimaryRoutes</code> and <code>AllowedIPs</code>, so standby routers count too) and exit-node status. Untagged devices belong to their user's <code>LoginName</code>. Devices with the same name get a numbered suffix. Roles aren't in that output, so set them by hand on the Inventory tab.</li>
          <li><strong>No inventory?</strong> Infer one from the policy: a laptop per user named in it, one device per tag, devices for tailnet IPs and LAN hosts used as sources, and a subnet router for the other addresses. It's a guess, so treat dead-rule lints on it with care.</li>
        </ul>

        <h2>Semantics and sources</h2>
        <p>Checked against Tailscale's public documentation on 16 November 2026.</p>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Topic</th><th>Behaviour</th><th>Source</th></tr></thead>
            <tbody>
              {RULES.map(([topic, rule, url]) => (
                <tr key={topic}><td>{topic}</td><td>{rule}</td><td><a href={url} target="_blank" rel="noreferrer">{new URL(url).pathname.split('/').filter(Boolean).slice(-2).join('/')}</a></td></tr>
              ))}
            </tbody>
          </table>
        </div>
        <p>Addresses are compared as 128-bit numbers, with IPv4 mapped into <code>::ffff:0:0/96</code>, so IPv4 and IPv6 CIDRs, hosts and ipsets (including <code>remove</code>) work the same way.</p>

        <h2>Tested against real policies</h2>
        <p>Fourteen public policy files from GitHub were run through the parser, linter and test runner. One of them ships as the <em>Real homelab</em> sample: <a href="https://github.com/mdlayher/homelab/blob/main/terraform/tailscale/policy.hujson" target="_blank" rel="noreferrer">mdlayher/homelab</a> (MIT licence, commit <code>e396dad</code>, owner login replaced with <code>admin@example.com</code>). It uses posture checks, Tailscale Services, IPv6 subnets, exit nodes and 19 test blocks. All 19 pass in Policy Lab, as they do in Tailscale. Its devices are made up to fit its tags.</p>
        <p>The status importer is tested on the field layout of real <code>tailscale status --json</code> output: <code>null</code> tags and routes, IPv6 addresses, the <code>tagged-devices</code> user and shared-in nodes.</p>

        <h2>Not covered</h2>
        <ul>
          <li>In the matrix and Why?, posture checks are assumed to pass (the trace says so) and <code>via</code> is assumed to route. Only tests evaluate posture.</li>
          <li>Each device is matched by one address, usually its IPv4. A rule that names a device's IPv6 tailnet address won't match it.</li>
          <li>App capabilities are listed, not interpreted. <code>nodeAttrs</code>, <code>postures</code> beyond assertions, and the SSH side of the diff aren't evaluated.</li>
          <li>This is an independent reimplementation, not Tailscale's evaluator. Confirm anything critical in the admin console.</li>
        </ul>

        <h2>Privacy</h2>
        <p>Everything runs in your browser. The workspace is saved in this browser's local storage, and share links keep the state in the URL fragment, which never reaches a server.</p>
      </main>
      <Footer />
    </div>
  )
}
