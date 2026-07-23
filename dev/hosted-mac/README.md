# Host a broker on a Mac, manage it from the desktop app

V0 hosted deployment: one broker per workspace, running headless on a Mac
(the same machine for testing, or a Mac mini / Mac server on your
network), managed remotely from AKA Desktop and used by agents on other
machines. TLS is your proxy or tunnel's job; the broker itself serves
plain HTTP on the address you give it.

## 1. On the broker Mac

Install the CLI (`npm install -g agentmfa`) or use a checkout. Then:

```sh
# Issue the management token (offline; stop any running broker first).
# Printed once — only its hash is stored. This is what you enter in the
# desktop app.
aka manage token

# Optionally seed tools/secrets offline (or do it all from the app later):
aka secret add GITHUB_API_KEY
aka conn add github --kind api --host api.github.com \
    --template 'Authorization: Bearer {{GITHUB_API_KEY}}'

# Serve. --listen adds the TCP control plane (loopback here; see below),
# --public-url is what remote clients will reach it at through your proxy.
aka serve --listen 127.0.0.1:4780 --public-url https://broker.example.dev
```

Notes:

- **Keychain needs a logged-in session.** The broker stores secret values
  in the macOS login Keychain, so run it inside a logged-in user session —
  a launchd *agent* (`~/Library/LaunchAgents`), never a launch *daemon*.
  A headless Mac mini works with auto-login enabled.
- **MCP host**: `aka serve` starts the Node sidecar when it finds
  `dist/sidecar/main.mjs` (a checkout after `npm run sidecar:build`) or
  `AKA_SIDECAR_SCRIPT` points at one; `node` must be on PATH (or set
  `AKA_SIDECAR_NODE`). Remote MCP clients then use `<public-url>/mcp`.
- `/v1/pair` is not served on the TCP listener: remote clients get the
  shared agent key from you (it lives in `~/.aka/token` on this Mac), and
  the desktop app manages the broker with the `akamgr_…` token only.

A LaunchAgent that keeps it running (edit the paths, then
`launchctl load ~/Library/LaunchAgents/com.aka.serve.plist`):
see [`com.aka.serve.plist`](com.aka.serve.plist) in this directory.

## 2. TLS in front

The TCP listener is plain HTTP by design. For same-machine testing,
`--listen 127.0.0.1:4780` needs nothing else. Across machines, put one of
these in front and use its address as `--public-url`:

- your hosting service's TLS proxy, forwarding to the broker Mac's port;
- a tunnel (Tailscale between your machines is the least setup: then
  `--listen` on the tailnet address and skip the proxy);
- an SSH tunnel for ad-hoc use:
  `ssh -N -L 4780:127.0.0.1:4780 user@broker-mac`.

The management token and secret values ride this connection — do not
expose the bare listener to an untrusted network.

## 3. In AKA Desktop (any machine)

Open the broker switcher at the right of the title bar → **Remote
broker…** → enter the URL and the `akamgr_…` token. The app manages the
hosted broker exactly like a local one; the switcher's dot shows the live
link. Switch back to **This Mac** anytime — the token stays saved (in
your login Keychain) per broker URL.

Not yet available against a remote broker (coming phases): browser OAuth
sign-ins (paste tokens instead) and direct endpoints; WebSocket/Postgres/
SSH data-plane opens still hand out broker-host-local addresses, so
agents using those must run on the broker Mac. HTTP tools and MCP work
from anywhere.

## 4. Agents on other machines

Point MCP clients at `<public-url>/mcp` with
`Authorization: Bearer <shared agent key>`; plain HTTP tools go through
`POST <public-url>/v1/http`. The app's Get started tab shows a
paste-ready setup message rendered for the broker you are managing.
