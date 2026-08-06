# Host a broker on Linux

The broker runs headless on Linux the same way it does on a Mac
(`multitool serve`), with one difference: **secrets are sealed by an encrypted
vault** instead of the macOS Keychain, so you must provide a master key.
Everything else — the manage API, the `akamgr_` token, TCP control plane,
relayed OAuth, data-plane advertise — works identically. Manage it from
Multitool Desktop exactly as you would a hosted Mac.

## The vault master key

On non-macOS the broker uses `EncryptedFileVault`: each secret value is
XChaCha20-Poly1305 sealed under a 32-byte master key you supply. The
state-integrity key rides the same vault, so tamper protection is sealed
too.

Generate a key and keep it somewhere your host injects as an environment
variable (a secret manager, a systemd `EnvironmentFile`, a Docker secret):

```sh
openssl rand -hex 32          # save these 64 hex chars in your secret manager
export AKA_VAULT_KEY='<paste the stored value>'
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
docker build -f dev/hosted-linux/Dockerfile -t multitool-broker .

# One broker per workspace, state on a named volume, key from your env:
: "${AKA_VAULT_KEY:?set AKA_VAULT_KEY before starting the broker}"
docker run -d --name multitool-broker \
    -e AKA_VAULT_KEY="$AKA_VAULT_KEY" \
    -p 4780:4780 \
    -v aka-state:/var/lib/aka \
    multitool-broker --public-url https://broker.example.dev --advertise-host broker.lan
```

The image builds the self-contained `multitool` CLI (glibc/Debian — no musl
needed); its in-process Rust MCP host serves `<public-url>/mcp`. Args after
the image name are appended to the entrypoint's
`multitool serve --root /var/lib/aka --listen 0.0.0.0:4780`.

On its first start, the broker writes a bounded bootstrap credential to
`/var/lib/aka/sock/manage-token` (mode 0600). Rotate it online immediately;
the CLI authenticates with that file, stores the replacement, and the broker
removes the bootstrap file:

```sh
docker exec multitool-broker multitool manage token --root /var/lib/aka
```

The command prints the replacement once; enter it in the desktop app. Future
rotations use the saved current token and also happen while the broker runs.
From another machine, store the current token with
`multitool manage login --broker <public-url>` and then rotate with
`multitool manage token --broker <public-url>`. Every management command drives the
**running** broker over its manage API — seed secrets and tools, flip agent
access, test connections, read the activity trail:

```sh
printf '%s' "$GITHUB_TOKEN" | multitool secret add GITHUB_TOKEN --broker https://broker.example.dev
multitool conn add github --kind api --host api.github.com \
    --template 'Authorization: Bearer {{GITHUB_TOKEN}}' --broker https://broker.example.dev
multitool conn disable github --broker https://broker.example.dev
multitool activity --broker https://broker.example.dev
```

## Run it (systemd, no container)

Build `multitool` (`cargo build --release -p multitool`), install it, create the `aka`
user and `/var/lib/aka`, and drop the key in `/etc/aka/vault.env`
(`AKA_VAULT_KEY=…`, mode 0400), then use
[`multitool-broker.service`](multitool-broker.service):

```sh
install -Dm755 target/release/multitool /usr/local/bin/multitool
useradd --system --home /var/lib/aka --create-home aka
install -Dm644 dev/hosted-linux/multitool-broker.service /etc/systemd/system/multitool-broker.service
# edit the unit's --public-url; put the key in /etc/aka/vault.env
systemctl daemon-reload && systemctl enable --now multitool-broker
```

## TLS, data planes, and the rest

Same as the Mac runbook (`dev/hosted-mac/`): put TLS in front of the TCP
port (reverse proxy or tunnel), `--data-plane-listen`/`--advertise-host`
for PG agents on other machines (the plaintext leg → trusted network only),
and SSH stays same-machine. `--ttl-days` on `multitool manage token` bounds a
leaked token.

## Still open

- **musl / Alpine:** the image uses glibc (Debian). An Alpine/musl build
  would need the musl cross-toolchain wired into `scripts/npm-dist.sh`;
  not done here.
- **Rootless / read-only rootfs:** the systemd unit sets basic hardening
  (`ProtectSystem=strict`, `NoNewPrivileges`), but a fully read-only
  container rootfs hasn't been validated.
