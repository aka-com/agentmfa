# A hosted Multitool broker for Linux: builds the self-contained `multitool` CLI, then
# runs it with the control plane on TCP and secrets in the encrypted vault.
# TLS is your reverse proxy's job; this image serves plain HTTP on 4780.
#
# Build from the repo root:
#   docker build -f dev/hosted-linux/Dockerfile -t multitool-broker .
# Run (see dev/hosted-linux/README.md for the full command and the vault key):
#   docker run -e AKA_VAULT_KEY=... -p 4780:4780 -v aka-state:/var/lib/aka multitool-broker

# --- build the multitool CLI (glibc; Debian base means no musl needed) ---
FROM rust:1-bookworm AS rust
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Build only the CLI + core (the desktop crate is excluded from the workspace
# and needs a webview toolchain we don't want in a server image).
RUN cargo build --release -p multitool

# --- runtime: slim glibc image ---
FROM debian:bookworm-slim AS runtime
# Testing an SSH tool authenticates a stock OpenSSH client against the target,
# so `ssh` has to be present in the otherwise-minimal runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 aka \
    && mkdir -p /var/lib/aka && chown aka:aka /var/lib/aka
COPY --from=rust /src/target/release/multitool /usr/local/bin/multitool

USER aka
ENV HOME=/home/aka
# Secrets live under a persistent volume; mount one at /var/lib/aka and point
# the broker root at it so state survives container restarts.
VOLUME ["/var/lib/aka"]
EXPOSE 4780

# The vault master key (AKA_VAULT_KEY) MUST be provided at runtime — the
# image ships no key. Without it the broker falls back to an unencrypted
# dev vault and logs a warning; a hosted deployment always sets it.
ENTRYPOINT ["multitool", "serve", "--root", "/var/lib/aka", "--listen", "0.0.0.0:4780"]
