//! Multitool broker core.
//!
//! Everything sensitive lives here: the secret store, the
//! injection-template engine, the wiring table, the audit log, and the
//! agent-facing daemon (control plane over a Unix domain socket; PG data
//! planes on ephemeral loopback TCP).
//!
//! The crate is deliberately portable: everything builds and tests on any
//! Unix. macOS-only integrations (the Keychain vault) are `cfg`-gated with
//! documented dev fallbacks, so the security-relevant logic is exercised by
//! tests everywhere.

pub mod approvals;
pub mod audit;
pub mod broker;
pub mod capability;
pub mod config;
pub mod daemon;
pub mod elicitations;
pub mod endpoints;
pub mod error;
pub mod events;
pub mod executions;
pub(crate) mod gcp_signer;
pub mod health;
pub mod identity;
pub mod integrity;
pub mod keychain;
pub mod manage;
pub mod mcp;
pub mod mcp_auth;
pub mod mcp_host;
pub(crate) mod mcp_refresh;
pub mod oauth;
pub mod onepassword;
pub mod password;
pub mod paths;
pub mod policy;
pub mod ratelimit;
pub mod repository;
pub mod request_history;
pub mod sessions;
pub(crate) mod sigv4;
pub mod store;
pub mod template;
pub mod totp;
pub mod types;
pub mod untrusted_text;
pub mod vault;
pub mod wire;

pub use error::CoreError;
pub type Result<T, E = CoreError> = std::result::Result<T, E>;
