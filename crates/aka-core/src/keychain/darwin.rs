//! The Security.framework binding behind [`super::KeychainApi`].
//!
//! One `SecItem` API serves both macOS keychains; `kSecUseDataProtectionKeychain`
//! is what picks between them, so [`Keychain`] is threaded into every query
//! rather than baked into the type. Everything else here is generic-password
//! plumbing: service + account identify the item, `kSecValueData` carries the
//! bytes, `kSecAttrLabel` is the title Keychain Access shows.
//!
//! This is the only part of the vault that cannot be tested off a signed Mac;
//! the policy that drives it — which keychain, when to migrate, what to label
//! things — lives in the parent module behind the `KeychainApi` seam and is
//! tested everywhere.

use std::ptr;

use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFTypeRef, OSStatus};
use core_foundation_sys::string::CFStringRef;
use security_framework_sys::access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
use security_framework_sys::base::{errSecItemNotFound, errSecSuccess, SecCopyErrorMessageString};
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrLabel, kSecAttrService, kSecAttrSynchronizable, kSecClass,
    kSecClassGenericPassword, kSecReturnData, kSecUseDataProtectionKeychain, kSecValueData,
};
use security_framework_sys::keychain_item::{
    SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate,
};
use zeroize::Zeroizing;

use super::{Keychain, KeychainApi, KeychainError, OsError};

/// `OSStatus` values `security-framework-sys` does not export.
const ERR_SEC_MISSING_ENTITLEMENT: OSStatus = -34018;
const ERR_SEC_USER_CANCELED: OSStatus = -128;
const ERR_SEC_AUTH_FAILED: OSStatus = -25293;
const ERR_SEC_INTERACTION_NOT_ALLOWED: OSStatus = -25308;

#[link(name = "Security", kind = "framework")]
extern "C" {
    /// `kSecAttrAccessible`, the key whose value says when a data-protection
    /// item may be read. Not exported by `security-framework-sys`, which only
    /// declares the values it takes.
    static kSecAttrAccessible: CFStringRef;
}

/// The Security.framework-backed [`KeychainApi`]. Stateless: every call
/// builds its own query, so there is no handle to keep alive and nothing to
/// synchronize.
#[derive(Debug, Default, Clone, Copy)]
pub struct SecurityFramework;

type Pairs = Vec<(CFString, CFType)>;

/// The attributes that identify one item, in one keychain.
///
/// `kSecUseDataProtectionKeychain` is set explicitly either way. False is
/// already the macOS default, but the two keychains are separate stores and
/// the difference decides whether reads prompt, so it is not left implicit.
fn base_query(keychain: Keychain, service: &str, account: &str) -> Pairs {
    // SAFETY: the `kSec*` statics are immortal CFString constants exported by
    // Security.framework; `wrap_under_get_rule` retains rather than consumes.
    unsafe {
        vec![
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassGenericPassword).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrService),
                CFString::new(service).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrAccount),
                CFString::new(account).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain),
                CFBoolean::from(keychain == Keychain::DataProtection).as_CFType(),
            ),
        ]
    }
}

fn dictionary(pairs: Pairs) -> CFDictionary<CFString, CFType> {
    CFDictionary::from_CFType_pairs(&pairs)
}

/// The value bytes, as an addition to a query or an item's attributes. The
/// copy CoreFoundation makes is freed without being zeroized — unavoidable
/// through `SecItem`, and the reason values are fetched one at a time and
/// dropped immediately rather than cached.
fn value_pair(value: &[u8]) -> (CFString, CFType) {
    unsafe {
        (
            CFString::wrap_under_get_rule(kSecValueData),
            CFData::from_buffer(value).as_CFType(),
        )
    }
}

fn label_pair(label: &str) -> (CFString, CFType) {
    unsafe {
        (
            CFString::wrap_under_get_rule(kSecAttrLabel),
            CFString::new(label).as_CFType(),
        )
    }
}

/// Security.framework's own description of a status, so the statuses we do
/// not enumerate still arrive as words rather than an integer to look up.
/// `None` when the framework has no text for it.
fn describe(status: OSStatus) -> Option<String> {
    // SAFETY: returns a +1 CFString, or null for a status it cannot describe.
    let raw = unsafe { SecCopyErrorMessageString(status, ptr::null_mut()) };
    if raw.is_null() {
        return None;
    }
    Some(unsafe { CFString::wrap_under_create_rule(raw) }.to_string())
}

fn os_error(status: OSStatus) -> OsError {
    OsError::described(status, describe(status))
}

/// Turn an `OSStatus` into the shapes callers branch on.
///
/// Written as comparisons rather than a `match`: the `errSec*` constants are
/// lower-case, and a lower-case path in a pattern is too easy to misread as an
/// irrefutable binding.
fn check(status: OSStatus) -> Result<(), KeychainError> {
    if status == errSecSuccess {
        return Ok(());
    }
    if status == errSecItemNotFound {
        return Err(KeychainError::NotFound);
    }
    if status == ERR_SEC_MISSING_ENTITLEMENT {
        return Err(KeychainError::MissingEntitlement);
    }
    if status == ERR_SEC_USER_CANCELED
        || status == ERR_SEC_AUTH_FAILED
        || status == ERR_SEC_INTERACTION_NOT_ALLOWED
    {
        return Err(KeychainError::NotAuthorized(os_error(status)));
    }
    Err(KeychainError::Os(os_error(status)))
}

impl KeychainApi for SecurityFramework {
    fn read(
        &self,
        keychain: Keychain,
        service: &str,
        account: &str,
    ) -> Result<Zeroizing<Vec<u8>>, KeychainError> {
        let mut pairs = base_query(keychain, service, account);
        // No `kSecMatchLimit`: the default is one item, and asking only for
        // the data means the result is that item's `CFData`.
        pairs.push(unsafe {
            (
                CFString::wrap_under_get_rule(kSecReturnData),
                CFBoolean::true_value().as_CFType(),
            )
        });
        let query = dictionary(pairs);

        let mut result: CFTypeRef = ptr::null();
        // SAFETY: `query` outlives the call, and `result` is a valid slot for
        // the one +1 reference the create rule hands back.
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
        check(status)?;
        if result.is_null() {
            return Err(KeychainError::NotFound);
        }
        // SAFETY: `SecItemCopyMatching` returns a +1 reference on success.
        let value = unsafe { CFType::wrap_under_create_rule(result) };
        let data = value
            .downcast_into::<CFData>()
            .ok_or_else(|| KeychainError::Malformed("expected the item's data".into()))?;
        Ok(Zeroizing::new(data.bytes().to_vec()))
    }

    fn write(
        &self,
        keychain: Keychain,
        service: &str,
        account: &str,
        label: &str,
        value: &[u8],
    ) -> Result<(), KeychainError> {
        // Update an existing item in place rather than deleting and re-adding
        // it: in the login keychain a fresh item would come back with a fresh
        // ACL, and every reader would be asked to approve it again.
        let query = dictionary(base_query(keychain, service, account));
        let updates = dictionary(vec![value_pair(value), label_pair(label)]);
        // SAFETY: both dictionaries outlive the call.
        let status =
            unsafe { SecItemUpdate(query.as_concrete_TypeRef(), updates.as_concrete_TypeRef()) };
        if status != errSecItemNotFound {
            return check(status);
        }

        let mut pairs = base_query(keychain, service, account);
        pairs.push(value_pair(value));
        pairs.push(label_pair(label));
        if keychain == Keychain::DataProtection {
            // Readable after the Mac's first unlock, so a relaunched or
            // headless broker is not blocked behind a locked screen, and
            // "ThisDeviceOnly" so values never ride a Keychain backup onto
            // another machine.
            pairs.push(unsafe {
                (
                    CFString::wrap_under_get_rule(kSecAttrAccessible),
                    CFString::wrap_under_get_rule(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
                        .as_CFType(),
                )
            });
            pairs.push(unsafe {
                (
                    CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                    CFBoolean::false_value().as_CFType(),
                )
            });
        }
        let attributes = dictionary(pairs);
        // SAFETY: `attributes` outlives the call; a null result slot means
        // "add it and return nothing".
        let status = unsafe { SecItemAdd(attributes.as_concrete_TypeRef(), ptr::null_mut()) };
        check(status)
    }

    fn relabel(
        &self,
        keychain: Keychain,
        service: &str,
        account: &str,
        label: &str,
    ) -> Result<(), KeychainError> {
        let query = dictionary(base_query(keychain, service, account));
        let updates = dictionary(vec![label_pair(label)]);
        // SAFETY: both dictionaries outlive the call.
        let status =
            unsafe { SecItemUpdate(query.as_concrete_TypeRef(), updates.as_concrete_TypeRef()) };
        check(status)
    }

    fn remove(
        &self,
        keychain: Keychain,
        service: &str,
        account: &str,
    ) -> Result<(), KeychainError> {
        let query = dictionary(base_query(keychain, service, account));
        // SAFETY: `query` outlives the call.
        let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
        check(status)
    }
}
