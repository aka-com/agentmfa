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
mfa manage token

# Optionally bound a leaked token's blast radius with an expiry; the app
# re-prompts for a fresh one when it lapses. Re-run to rotate, --revoke
# to close the manage API.
mfa manage token --ttl-days 90

# Optionally seed tools/secrets offline (or do it all from the app later,
# or live once the broker is up: `mfa manage login`, then the same
# commands drive the running broker — remotely too, with
# `--broker <public-url>`):
mfa secret add GITHUB_API_KEY
mfa conn add github --kind api --host api.github.com \
    --template 'Authorization: Bearer {{GITHUB_API_KEY}}'

# Serve. --listen adds the TCP control plane (loopback here; see below),
# --public-url is what remote clients will reach it at through your proxy.
mfa serve --listen 127.0.0.1:4780 --public-url https://broker.example.dev
```

Notes:

- **Keychain needs a logged-in session.** The broker stores secret values
  in the macOS Keychain, so run it inside a logged-in user session —
  a launchd *agent* (`~/Library/LaunchAgents`), never a launch *daemon*.
  A headless Mac mini works with auto-login enabled. Items are stored
  `AfterFirstUnlock`, so the broker keeps reading once the Mac has been
  unlocked once after boot; it cannot read before that.
- **`mfa serve` uses the login Keychain, and it prompts.** The
  data-protection keychain that makes reads silent is gated on a
  `keychain-access-groups` entitlement, which the unsigned `mfa` binary does
  not carry. On a headless box that means an approval dialog per secret, per
  build of `mfa` — click *Always Allow* once per item, or sign your own `mfa`
  build. `mfa status` prints which keychain is in use. If this host also runs
  the signed desktop app against the same store, see the note in
  `crates/aka-core/src/keychain/mod.rs`: the app moves values somewhere `mfa`
  cannot follow, and `mfa` will say so rather than show an empty vault.
- **MCP host**: `mfa serve` starts the in-process Rust host automatically.
  Remote MCP clients use `<public-url>/mcp`.
- `/v1/pair` is not served on the TCP listener: remote clients get the
  shared agent key from you (`mfa key` prints it; it lives in
  `~/.aka/token` on this Mac), and the desktop app manages the broker
  with the `akamgr_…` token only.

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
your Keychain) per broker URL.

Browser OAuth sign-ins (BYO-app and MCP) are relayed — the consent page
opens in *your* browser, the token stays on the broker. Direct endpoints
issue remotely too.

For agents on other machines to use the **Postgres** data plane, serve it
on a reachable address:

```sh
mfa serve --listen 127.0.0.1:4780 --public-url https://broker.example.dev \
    --data-plane-listen 0.0.0.0 --advertise-host broker.lan
```

`--data-plane-listen` binds the PG proxy (and the HTTP direct endpoint) to
that address; `--advertise-host` is the host put in the `postgres://…`
addresses agents receive. **These legs are
plaintext** (the loopback contract), so keep them on a trusted LAN or
tunnel — never the open internet.

**SSH is the remaining same-machine plane.** `/v1/ssh/open` and the SSH
direct endpoint hand back a Unix-socket path for `SSH_AUTH_SOCK`, which
only exists on the broker Mac. An agent needing SSH must run on the
broker host (or forward the agent socket over its own SSH connection);
a networked SSH-agent bridge is future work. Postgres/SSH *direct
endpoints* are likewise broker-host sockets; only the HTTP endpoint's
address is reachable off-box.

## 4. Agents on other machines

Point MCP clients at `<public-url>/mcp` with
`Authorization: Bearer <shared agent key>`; plain HTTP tools go through
`POST <public-url>/v1/http`. The app's Get started tab shows a
paste-ready setup message rendered for the broker you are managing.
