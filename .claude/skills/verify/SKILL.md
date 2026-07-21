---
name: verify
description: >-
  Drive the Multitool broker end-to-end on any platform (no desktop UI
  needed) to verify control-plane changes at the real surface: HTTP over
  the Unix socket.
---

# Verifying Multitool changes

The agent-facing surface is HTTP over a Unix domain socket. The headless
CLI runs the whole broker (control plane + WS/PG data planes) anywhere,
including Linux where the Tauri app doesn't build.

## Launch

```sh
cargo build --workspace                          # binary: target/debug/aka
./target/debug/aka serve --root "$DIR/root" >"$DIR/serve.log" 2>&1 &
```

The socket is `<root>/sock/broker.sock`. On Linux the vault falls back to
a plaintext dev FileVault (warning in the log; expected).

## Seed connections

Seed the store with the CLI **before starting the broker** (the commands
refuse while a broker is live on the root):

```sh
printf 'dummy' | ./target/debug/aka secret add GITHUB_API_KEY --root "$DIR/root"
./target/debug/aka conn add github --kind api --host api.github.com \
    --template 'Authorization: Bearer {{GITHUB_API_KEY}}' --root "$DIR/root"
./target/debug/aka conn list --root "$DIR/root"
```

pg/ws/ssh kinds bind one secret by name (`--secret NAME`); `conn add`
validates like the app does, so template refs must name existing secrets.
Listing/wiring/404 flows never execute upstream, so a dummy value is fine;
executing `/v1/http` for real needs a real value and a reachable host.

## Drive

```sh
curl -s --unix-socket $SOCK http://localhost/.well-known/agent-broker.json
curl -s --unix-socket $SOCK -X POST http://localhost/v1/pair \
     -H "Content-Type: application/json" -d '{"agent_name": "claude-code"}'
curl -s --unix-socket $SOCK -H "Authorization: Bearer $TOKEN" http://localhost/v1/whoami
curl -s --unix-socket $SOCK -H "Authorization: Bearer $TOKEN" http://localhost/v1/connections
```

Gotchas:
- Pairing registers instantly (no approval). The **first** agent to pair
  on a fresh root is auto-wired to every seeded connection; later agents
  start unwired and their capability calls 403 `denied_by_policy` (there
  is no wire-protocol way to change wirings — pair the agent you're
  testing first, or exercise the refusal path with a second agent).
- Pairing is globally rate limited (3 per 5 s): `sleep 5` between bursts
  or unrelated probes will 429.
- `pkill -f "aka serve"` to clean up.
