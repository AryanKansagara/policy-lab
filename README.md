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

Supports `groups`, `tagOwners`, `hosts`, `ipsets`, autogroups, `acls`, `grants` (`ip`, `app`, `via`, `svc:` services), `ssh`, `tests` (with `srcPostureAttrs`), `sshTests`, `postures`, `defaultSrcPosture` and `autoApprovers`, following Tailscale's public documentation. IPv4 and IPv6 share one 128-bit address space, and `autogroup:internet` covers public addresses only.

The semantics, their sources and the real data used to check them are listed at [/docs](https://policy-lab-delta.vercel.app/docs). The "Real homelab" sample is a published policy from [mdlayher/homelab](https://github.com/mdlayher/homelab) (MIT), and all 19 of its test blocks pass here as they do in Tailscale.

This is an independent reimplementation, not Tailscale's evaluator, so confirm anything critical in the admin console. Known limits:

- In the matrix and Why?, posture checks are assumed to pass and `via` is assumed to route; both are noted in the trace. Tests evaluate posture.
- Each device is matched by one address (usually its IPv4), so a rule naming a device's IPv6 tailnet address will not match it.
- App capabilities are listed, not interpreted. The diff covers network access, not SSH rules.

## Run locally

```sh
npm install
npm run dev
npm test
npm run build
```

Built with Vite, React 19 and TypeScript, with no runtime dependencies beyond React.

## Tests and CI

- `npm test` runs the engine's unit tests with Node's built-in runner.
- `npm run test:e2e` builds the app and runs a Playwright (Chromium) suite against the production build served by `vite preview`. It needs the browser once: `npx playwright install chromium` (add `--with-deps` on a fresh Linux machine). Set `E2E_PORT` if port 4173 is taken. The suite runs signed out, blocks every external request (it fails if the app asks for anything beyond Google Fonts) and fails on any uncaught page error.
- GitHub Actions runs `npm ci`, the build, the unit tests and the E2E suite on every pull request and every push to `main` (job `test`, Node 22, with the Playwright browser cached by version). On a failure the Playwright report and traces are uploaded as an artifact.
- Vercel deploys `main` only (`git.deploymentEnabled` in `vercel.json`), so pull request branches get no preview. GitHub Actions is the gate.

Built by Aryan Kansagara.
