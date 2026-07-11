FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --release -p agentmfa-sandbox

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

COPY --from=builder /src/target/release/agentmfa-sandbox /usr/local/bin/agentmfa-sandbox
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/agentmfa-sandbox"]
