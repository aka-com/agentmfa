# A hosted AKA broker for Linux: builds the `mfa` CLI and the Node MCP
# sidecar, then runs `mfa serve` with the control plane on TCP and secrets
# in the encrypted vault. TLS is your reverse proxy's job (see the runbook);
# this image serves plain HTTP on 4780.
#
# Build from the repo root:
#   docker build -f dev/hosted-linux/Dockerfile -t aka-broker .
# Run (see dev/hosted-linux/README.md for the full command and the vault key):
#   docker run -e AKA_VAULT_KEY=... -p 4780:4780 -v aka-state:/var/lib/aka aka-broker

# --- build the mfa CLI (glibc; Debian base means no musl needed) ---
FROM rust:1-bookworm AS rust
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Build only the CLI + core (the desktop crate is excluded from the workspace
# and needs a webview toolchain we don't want in a server image).
RUN cargo build --release -p mfa

# --- build the MCP sidecar bundle ---
FROM node:22-bookworm-slim AS sidecar
WORKDIR /src
COPY package.json package-lock.json ./
COPY tsconfig.json vite.config.ts ./
COPY sidecar ./sidecar
COPY scripts ./scripts
RUN npm ci --no-audit --no-fund
RUN npm run sidecar:build

# --- runtime: slim glibc image with Node for the sidecar ---
FROM node:22-bookworm-slim AS runtime
# `mfa serve` supervises the sidecar and needs `node` on PATH (present in
# this base image). Testing an SSH tool authenticates a stock OpenSSH client
# against the target, so `ssh` has to be here too — the slim base omits it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 aka \
    && mkdir -p /var/lib/aka && chown aka:aka /var/lib/aka
COPY --from=rust /src/target/release/mfa /usr/local/bin/mfa
COPY --from=sidecar /src/dist/sidecar/main.mjs /usr/local/share/aka/sidecar/main.mjs

USER aka
ENV HOME=/home/aka \
    AKA_SIDECAR_SCRIPT=/usr/local/share/aka/sidecar/main.mjs
# Secrets live under a persistent volume; mount one at /var/lib/aka and point
# the broker root at it so state survives container restarts.
VOLUME ["/var/lib/aka"]
EXPOSE 4780

# The vault master key (AKA_VAULT_KEY) MUST be provided at runtime — the
# image ships no key. Without it the broker falls back to an unencrypted
# dev vault and logs a warning; a hosted deployment always sets it.
ENTRYPOINT ["mfa", "serve", "--root", "/var/lib/aka", "--listen", "0.0.0.0:4780"]
