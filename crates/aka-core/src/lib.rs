//! AKA broker core.
//!
//! Everything sensitive lives here: the secret store, the
//! injection-template engine, the wiring table, the audit log, and the
//! agent-facing daemon (control plane over a Unix domain socket; WS/PG data
//! planes on ephemeral loopback TCP).
//!
//! The crate is deliberately portable: everything builds and tests on any
//! Unix. macOS-only integrations (the Keychain vault) are `cfg`-gated with
//! documented dev fallbacks, so the security-relevant logic is exercised by
//! tests everywhere.

pub mod audit;
mod authorization;
pub mod broker;
pub mod capability;
pub mod config;
pub mod daemon;
pub mod error;
pub mod events;
pub mod executions;
pub mod integrity;
pub mod mcp;
pub mod mcp_auth;
pub mod pairing;
pub mod paths;
pub mod policy;
pub mod ratelimit;
pub mod sessions;
pub mod sidecar;
pub mod store;
pub mod template;
pub mod types;
pub mod vault;
pub mod wire;

pub use error::CoreError;
pub type Result<T, E = CoreError> = std::result::Result<T, E>;
