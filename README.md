# Policy Lab

A simulator and debugger for Tailscale tailnet policy files. Paste your HuJSON, describe your users and devices, and see who can reach what, why a connection is denied, and what a change would open up.

Live: https://policy-lab-delta.vercel.app

## The pain

A policy file controls every path on your network and grows one pull request at a time. Tests only catch what someone thought to assert. Nobody can say with confidence what a rule edit opens or closes, and a denied connection gives you no reason why. Policy Lab answers both before the change merges.

## Features

- **Editor**: HuJSON with comments and trailing commas, syntax highlighting, and precise line and column errors.
- **Access matrix**: every device against every destination, subnet and exit node, filterable by port.
- **Why?**: pick a source, destination and port to get the verdict, the exact rules lit up in the editor, near misses, and the SSH result.
- **Tests**: runs the policy's own `tests` and `sshTests` blocks, linking each failure to its rule.
- **Policy diff**: compares a baseline with the proposed policy and lists connections gained and lost.
- **Lints**: unused groups and tags, tags without owners, broad rules, shadowed rules, dead rules, root SSH without check mode, routes that need manual approval.
- **Graph**: hand-rolled SVG force layout of identities and allowed paths, with simulated traffic judged by the evaluator.
- **Your data**: edit the inventory, infer it from the policy, or import `tailscale status --json`. Upload a policy file or use one of three samples.
- **Private by default**: everything runs in the browser. Share links keep the state in the URL fragment, which never reaches a server.

## Coverage and limits

Supports `groups`, `tagOwners`, `hosts`, `ipsets`, autogroups, `acls`, `grants` (`ip`, `app`, `via`), `ssh`, `tests`, `sshTests` and `autoApprovers`, following Tailscale's public documentation.

This is an independent reimplementation, not Tailscale's evaluator, so confirm anything critical in the admin console. Known limits:

- CIDR math is IPv4 only. IPv6 addresses match exactly.
- `srcPosture` is assumed to pass and `via` is assumed to route, and both are noted in the trace.
- The diff covers network access, not SSH rules.

## Run locally

```sh
npm install
npm run dev
npm test
npm run build
```

Built with Vite, React 19 and TypeScript, with no runtime dependencies beyond React.

Built by Aryan Kansagara. Independent project, not affiliated with Tailscale.
