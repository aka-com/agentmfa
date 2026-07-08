//! Core-owned OS confirmation (DESIGN.md §8).
//!
//! High-consequence commands, approving a pairing or a mutating request,
//! saving an "Always allow…" rule, creating/editing a connection, complete
//! only after a native LocalAuthentication (Touch ID / account password)
//! sheet that the webview cannot render, forge, or dismiss. The webview
//! *requests* the decision through a Tauri command, but the command runs
//! this gate in the Rust core before it takes effect.
//!
//! The read-time secret setting uses this same `LAContext` gate before
//! broker-side vault reads, so it works whether or not iCloud sync is on.

/// Prompt for the native OS confirmation with `reason` shown to the user.
/// Returns Ok(()) only when the user authenticated. Non-macOS builds fail
/// closed because the product currently relies on macOS LocalAuthentication.
pub fn confirm(reason: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        macos::confirm(reason)
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Proper non-macOS support needs an equivalent native confirmation
        // gate before these high-consequence actions can be enabled there.
        tracing::warn!(
            "OS confirmation unavailable on non-macOS build (reason: {reason}): \
             refusing high-consequence action"
        );
        Err("native confirmation is only supported on macOS in this build".into())
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::sync::mpsc;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    pub fn confirm(reason: &str) -> Result<(), String> {
        // LAPolicy::DeviceOwnerAuthentication → Touch ID with a graceful
        // fallback to the account password (unlike …WithBiometrics, which
        // fails on Macs without Touch ID).
        let policy = LAPolicy::DeviceOwnerAuthentication;
        let context = unsafe { LAContext::new() };

        // Bail early if the device can't evaluate the policy at all, but a
        // machine that genuinely cannot authenticate must not silently pass,
        // so we surface the error rather than allowing.
        if let Err(err) = unsafe { context.canEvaluatePolicy_error(policy) } {
            return Err(err.localizedDescription().to_string());
        }

        let ns_reason = NSString::from_str(reason);
        let (tx, rx) = mpsc::channel::<Result<(), String>>();

        // The completion block hops back on an arbitrary queue; forward the
        // result through a channel and block this command until it lands.
        let handler = RcBlock::new(move |success: Bool, error: *mut NSError| {
            let result = if success.as_bool() {
                Ok(())
            } else if error.is_null() {
                Err("authentication was cancelled".to_string())
            } else {
                let e = unsafe { &*error };
                Err(e.localizedDescription().to_string())
            };
            let _ = tx.send(result);
        });

        unsafe {
            context.evaluatePolicy_localizedReason_reply(policy, &ns_reason, &handler);
        }

        rx.recv()
            .unwrap_or_else(|_| Err("authentication channel closed".into()))
    }
}
