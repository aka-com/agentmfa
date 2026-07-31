# Hosting AgentMFA

Hosted mode is intended for one trusted user, workspace, or automation trust
domain per broker. It is not a multi-tenant identity or policy service.

## Trust model

- One shared agent key authorizes every agent-plane call. The optional
  `X-AgentMFA-Client` label is self-reported attribution, not authentication.
  Do not use one broker to isolate mutually untrusted users or agents.
- The management token is administrator authority. On a headless broker it
  substitutes for native user presence when a gated configuration action is
  required. Activity marks those actions as authorized via
  `management_token` and records the socket peer on the remote decision
  surface. Behind a reverse proxy that peer is the proxy. Neither field
  authenticates or identifies the human who used the token.
- The activity log is a local, integrity-chained operational history, not an
  immutable compliance log. A management-token holder can clear it; the new
  chain starts with an `activity_cleared` tombstone. Export logs to an
  independently controlled system if you need durable accountability.
- A remote request inbox can answer traffic confirmations only while its
  authenticated event stream holds and heartbeats an approval-surface lease.
  A passive event observer grants no such capability. If no surface is live,
  confirmed traffic fails closed.

## Network boundary

`mfa serve --listen` speaks plaintext HTTP. Put an authenticated TLS reverse
proxy or private tunnel in front of it and advertise only the HTTPS origin
with `--public-url`. TCP does not expose `/v1/pair`; provision the shared agent
key out of band. Restrict both the control listener and proxy with host
firewalls even when TLS is present.

The data planes are separate:

- HTTP direct endpoints and the broker-facing Postgres leg are plaintext.
- A non-loopback `--data-plane-listen` is refused unless
  `--data-plane-insecure` explicitly acknowledges that tickets, requests, and
  results can be observed on that network.
- `--advertise-host` changes the address returned to agents; it does not add
  TLS or authentication beyond each endpoint/ticket credential.
- SSH opens are refused on remote TCP because the returned agent socket is a
  same-machine capability.

Keep data planes loopback-only unless agents reach the host through a private
tunnel. Never expose their ports directly to the public Internet.

## Credentials and revocation

Store `AKA_VAULT_KEY` or `AKA_VAULT_KEY_FILE` outside the broker data
directory and inject it through the hosting platform's secret mechanism.
Management tokens are stored in a plaintext 0600 file on non-macOS clients;
prefer `AKA_MANAGE_TOKEN` in CI. The default management-token lifetime is 30
days. A never-managed broker writes one bounded first-start credential to its
owner-only socket directory. `mfa manage token` consumes it to perform the
first authenticated online rotation; subsequent rotations require the still
current saved or environment token and do not stop the broker.

Disabling a connection refuses new calls and closes transports the broker
owns. Rotating the shared agent key revokes outstanding tickets and direct
endpoints and closes broker-owned sessions. Neither action can terminate an
SSH process that already authenticated, because the broker is no longer in
that connection's data path.

Direct-endpoint secrets are standing broker credentials. Treat them like API
keys, transport them only over the trusted network described above, and
reissue them after suspected exposure.

## Recommended topology

1. Run one broker per trust domain under a dedicated OS account.
2. Keep its control and data-plane binds on loopback or a private interface.
3. Terminate HTTPS at a reverse proxy or tunnel that forwards only the
   intended control-plane routes.
4. Store the vault key, management token, and shared agent key in separate
   secret-distribution channels.
5. Export activity to external storage if retention matters, and test key
   rotation and connection-disable procedures before relying on them.

The development runbooks in `dev/hosted-mac/` and `dev/hosted-linux/` are
examples, not substitutes for this threat model.
