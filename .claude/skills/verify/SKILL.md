---
name: verify
description: >-
  Drive the AgentMFA broker end-to-end on any platform (no desktop UI
  needed) to verify control-plane changes at the real surface: HTTP over
  the Unix socket.
---

# Verifying AgentMFA changes

The agent-facing surface is HTTP over a Unix domain socket. The headless
CLI runs the whole broker (control plane + WS/PG data planes) anywhere,
including Linux where the Tauri app doesn't build.

## Launch

```sh
cargo build --workspace                          # binary: target/debug/agentmfa

# Auto-approving broker (happy paths):
./target/debug/agentmfa serve --root "$DIR/rootA" --yes >"$DIR/serveA.log" 2>&1 &

# Auto-DENYING broker (denial/cooldown paths): the terminal approver
# treats EOF on stdin as Deny, so </dev/null denies every prompt.
./target/debug/agentmfa serve --root "$DIR/rootB" </dev/null >"$DIR/serveB.log" 2>&1 &
```

The socket is `<root>/sock/broker.sock`. On Linux the vault falls back to
a plaintext dev FileVault (warning in the log; expected).

## Seed connections

Seed the store with the CLI **before starting the broker** (the commands
refuse while a broker is live on the root):

```sh
printf 'dummy' | ./target/debug/agentmfa secret add GITHUB_API_KEY --root "$DIR/rootA"
./target/debug/agentmfa conn add github --kind api --host api.github.com \
    --template 'Authorization: Bearer {{GITHUB_API_KEY}}' --root "$DIR/rootA"
./target/debug/agentmfa conn list --root "$DIR/rootA"
```

pg/ws/ssh kinds bind one secret by name (`--secret NAME`); `conn add`
validates like the app does, so template refs must name existing secrets.
Listing/policy/404 flows never execute upstream, so a dummy value is fine;
executing `/v1/http` for real needs a real value and a reachable host.

## Drive

```sh
curl -s --unix-socket $SOCK http://localhost/.well-known/agent-broker.json
curl -s --unix-socket $SOCK -X POST http://localhost/v1/pair \
     -H "Content-Type: application/json" -d '{"agent_name": "claude-code"}'
curl -s --unix-socket $SOCK -H "Authorization: Bearer $TOKEN" http://localhost/v1/whoami
```

Gotchas:
- Pairing is globally rate limited (3 per 5 s): `sleep 5` between bursts
  or unrelated probes will 429.
- A user denial arms a 30 s pairing cooldown (broker-wide).
- Prompted calls block (held-open) until decided; `--yes` decides
  instantly, the `</dev/null` broker denies instantly.
- `pkill -f "agentmfa serve"` to clean up.
