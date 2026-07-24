# Host a broker on Linux

The broker runs headless on Linux the same way it does on a Mac
(`aka serve`), with one difference: **secrets are sealed by an encrypted
vault** instead of the macOS Keychain, so you must provide a master key.
Everything else — the manage API, the `akamgr_` token, TCP control plane,
relayed OAuth, data-plane advertise — works identically. Manage it from
AKA Desktop exactly as you would a hosted Mac.

## The vault master key

On non-macOS the broker uses `EncryptedFileVault`: each secret value is
XChaCha20-Poly1305 sealed under a 32-byte master key you supply. The
state-integrity key rides the same vault, so tamper protection is sealed
too.

Generate a key and keep it somewhere your host injects as an environment
variable (a secret manager, a systemd `EnvironmentFile`, a Docker secret):

```sh
openssl rand -hex 32          # 64 hex chars → AKA_VAULT_KEY
```

Provide it one of two ways:

- `AKA_VAULT_KEY=<64 hex or base64>` — the key value directly, or
- `AKA_VAULT_KEY_FILE=/path/to/key` — a file holding the key (hex/base64
  text, or 32 raw bytes).

**Without a key the broker falls back to an unencrypted dev vault and logs
a warning** — never do that in production. **If you lose the key, the
sealed secrets are unrecoverable** (re-add them). A wrong key fails fast at
startup rather than silently.

## Run it (Docker)

```sh
# From the repo root:
docker build -f dev/hosted-linux/Dockerfile -t aka-broker .

# One broker per workspace, state on a named volume, key from your env:
docker run -d --name aka-broker \
    -e AKA_VAULT_KEY="$AKA_VAULT_KEY" \
    -p 4780:4780 \
    -v aka-state:/var/lib/aka \
    aka-broker --public-url https://broker.example.dev --advertise-host broker.lan
```

The image builds the `aka` CLI (glibc/Debian — no musl needed) and the
Node MCP sidecar, and `aka serve` supervises the sidecar so `<public-url>/mcp`
works. Args after the image name are appended to the entrypoint's
`aka serve --root /var/lib/aka --listen 0.0.0.0:4780`.

Issue the management token once (offline; the broker holds identity state
in memory, so stop it first), then enter it in the desktop app:

```sh
docker stop aka-broker
docker run --rm -e AKA_VAULT_KEY="$AKA_VAULT_KEY" -v aka-state:/var/lib/aka \
    --entrypoint aka aka-broker manage token --root /var/lib/aka
docker start aka-broker
```

That one-time issuance is the only stop/start: with the token stored
(`aka manage login --broker <public-url>`, from any machine with the
CLI), every management command drives the **running** broker over its
manage API — seed secrets and tools, flip agent access, test
connections, read the activity trail:

```sh
printf '%s' "$GITHUB_TOKEN" | aka secret add GITHUB_TOKEN --broker https://broker.example.dev
aka conn add github --kind api --host api.github.com \
    --template 'Authorization: Bearer {{GITHUB_TOKEN}}' --broker https://broker.example.dev
aka conn disable github --broker https://broker.example.dev
aka activity --broker https://broker.example.dev
```

## Run it (systemd, no container)

Build `aka` (`cargo build --release -p aka`) and the sidecar
(`npm run sidecar:build`), install them, create the `aka` user and
`/var/lib/aka`, drop the key in `/etc/aka/vault.env`
(`AKA_VAULT_KEY=…`, mode 0400), then use
[`aka-broker.service`](aka-broker.service):

```sh
install -Dm755 target/release/aka /usr/local/bin/aka
install -Dm644 dist/sidecar/main.mjs /usr/local/share/aka/sidecar/main.mjs
useradd --system --home /var/lib/aka --create-home aka
install -Dm644 dev/hosted-linux/aka-broker.service /etc/systemd/system/aka-broker.service
# edit the unit's --public-url; put the key in /etc/aka/vault.env
systemctl daemon-reload && systemctl enable --now aka-broker
```

## TLS, data planes, and the rest

Same as the Mac runbook (`dev/hosted-mac/`): put TLS in front of the TCP
port (reverse proxy or tunnel), `--data-plane-listen`/`--advertise-host`
for WS/PG agents on other machines (plaintext legs → trusted network only),
and SSH stays same-machine. `--ttl-days` on `aka manage token` bounds a
leaked token.

## Still open

- **musl / Alpine:** the image uses glibc (Debian). An Alpine/musl build
  would need the musl cross-toolchain wired into `scripts/npm-dist.sh`;
  not done here.
- **Rootless / read-only rootfs:** the systemd unit sets basic hardening
  (`ProtectSystem=strict`, `NoNewPrivileges`), but a fully read-only
  container rootfs hasn't been validated.
