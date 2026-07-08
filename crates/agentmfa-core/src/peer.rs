//! Peer verification over the Unix domain socket (DESIGN.md §8).
//!
//! On every UDS accept the broker resolves the connecting peer's identity:
//!
//! - **macOS**: read the peer's **audit token** (`LOCAL_PEERTOKEN`, race-
//!   free, unlike PID lookups) and feed it to
//!   `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)` →
//!   `SecCodeCheckValidity` → `SecCodeCopySigningInformation`, yielding the
//!   signing identifier and Team ID. Validity alone proves little, the
//!   check is anchored at pairing time, when the token is pinned to the
//!   identity observed here.
//! - **elsewhere (dev builds)**: no code-signature oracle exists; the
//!   identity is the peer UID (`SO_PEERCRED`), a documented dev divergence.

use tokio::net::UnixStream;

use crate::types::PeerIdentity;

/// Resolve the peer's identity at accept time.
pub fn resolve_peer(stream: &UnixStream) -> PeerIdentity {
    #[cfg(target_os = "macos")]
    {
        macos::resolve(stream)
    }
    #[cfg(not(target_os = "macos"))]
    {
        match stream.peer_cred() {
            Ok(cred) => PeerIdentity::DevUnverified { uid: cred.uid() },
            Err(e) => {
                tracing::warn!("peer_cred failed: {e}");
                PeerIdentity::Unsigned
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use core_foundation::base::{CFType, TCFType, ToVoid};
    use core_foundation::data::CFData;
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::string::{CFString, CFStringRef};
    use std::os::fd::AsRawFd;

    // <sys/un.h>, options at the SOL_LOCAL level.
    const SOL_LOCAL: libc::c_int = 0;
    /// getsockopt option returning the peer's audit token (audit_token_t).
    const LOCAL_PEERTOKEN: libc::c_int = 0x006;

    /// audit_token_t
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct AuditToken {
        val: [u32; 8],
    }

    #[repr(C)]
    struct OpaqueSecCode {
        _private: [u8; 0],
    }
    type SecCodeRef = *mut OpaqueSecCode;
    type OSStatus = i32;
    type SecCSFlags = u32;

    const K_SEC_CS_DEFAULT_FLAGS: SecCSFlags = 0;
    /// kSecCSSigningInformation
    const K_SEC_CS_SIGNING_INFORMATION: SecCSFlags = 1 << 1;

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecGuestAttributeAudit: CFStringRef;
        static kSecCodeInfoIdentifier: CFStringRef;
        static kSecCodeInfoTeamIdentifier: CFStringRef;

        fn SecCodeCopyGuestWithAttributes(
            host: *const std::ffi::c_void,
            attributes: CFDictionaryRef,
            flags: SecCSFlags,
            guest: *mut SecCodeRef,
        ) -> OSStatus;
        fn SecCodeCheckValidity(
            guest: SecCodeRef,
            flags: SecCSFlags,
            requirement: *const std::ffi::c_void,
        ) -> OSStatus;
        fn SecCodeCopySigningInformation(
            code: SecCodeRef,
            flags: SecCSFlags,
            information: *mut CFDictionaryRef,
        ) -> OSStatus;
    }

    fn peer_audit_token(stream: &UnixStream) -> Option<AuditToken> {
        let fd = stream.as_raw_fd();
        let mut token = AuditToken { val: [0; 8] };
        let mut len = std::mem::size_of::<AuditToken>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERTOKEN,
                &mut token as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc == 0 && len as usize == std::mem::size_of::<AuditToken>() {
            Some(token)
        } else {
            tracing::warn!("LOCAL_PEERTOKEN getsockopt failed (rc={rc})");
            None
        }
    }

    pub(super) fn resolve(stream: &UnixStream) -> PeerIdentity {
        let Some(token) = peer_audit_token(stream) else {
            return PeerIdentity::Unsigned;
        };
        // SAFETY: plain FFI into Security.framework with owned CF objects.
        unsafe {
            let token_bytes: [u8; 32] = std::mem::transmute(token.val);
            let data = CFData::from_buffer(&token_bytes);
            let key = CFString::wrap_under_get_rule(kSecGuestAttributeAudit);
            let attrs = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), data.as_CFType())]);

            let mut code: SecCodeRef = std::ptr::null_mut();
            let status = SecCodeCopyGuestWithAttributes(
                std::ptr::null(),
                attrs.as_concrete_TypeRef(),
                K_SEC_CS_DEFAULT_FLAGS,
                &mut code,
            );
            if status != 0 || code.is_null() {
                tracing::warn!("SecCodeCopyGuestWithAttributes failed ({status})");
                return PeerIdentity::Unsigned;
            }
            // Ensure release on all paths.
            struct Release(SecCodeRef);
            impl Drop for Release {
                fn drop(&mut self) {
                    unsafe {
                        core_foundation::base::CFRelease(self.0 as *const _);
                    }
                }
            }
            let _release = Release(code);

            if SecCodeCheckValidity(code, K_SEC_CS_DEFAULT_FLAGS, std::ptr::null()) != 0 {
                // Invalid or ad-hoc/unsigned, the pairing dialog calls this
                // out loudly (§6).
                return PeerIdentity::Unsigned;
            }

            let mut info: CFDictionaryRef = std::ptr::null();
            let status =
                SecCodeCopySigningInformation(code, K_SEC_CS_SIGNING_INFORMATION, &mut info);
            if status != 0 || info.is_null() {
                return PeerIdentity::Unsigned;
            }
            let info: CFDictionary<CFString, CFType> =
                CFDictionary::wrap_under_create_rule(info as *mut _);

            let get_string = |key: CFStringRef| -> Option<String> {
                let key = CFString::wrap_under_get_rule(key);
                info.find(key.to_void() as *const _)
                    .and_then(|v| v.downcast::<CFString>())
                    .map(|s| s.to_string())
            };

            match get_string(kSecCodeInfoIdentifier) {
                Some(signing_id) => PeerIdentity::Signed {
                    signing_id,
                    team_id: get_string(kSecCodeInfoTeamIdentifier),
                },
                None => PeerIdentity::Unsigned,
            }
        }
    }
}
