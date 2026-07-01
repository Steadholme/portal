//! Gateway-injected identity.
//!
//! Portal does NO login of its own. It sits behind a Sluice `auth=sso` route on the apex
//! host `w33d.xyz`, where the gateway runs the OIDC browser login against Keystone, STRIPS
//! any inbound `X-Auth-*`, and injects the verified `X-Auth-Subject` / `X-Auth-Email`.
//! Because Portal is internal-only (never publicly reachable except through Sluice), it
//! TRUSTS the injected `X-Auth-Email` as the signed-in user.

use axum::http::HeaderMap;

pub const HEADER_EMAIL: &str = "x-auth-email";
pub const HEADER_SUBJECT: &str = "x-auth-subject";
pub const HEADER_GROUPS: &str = "x-auth-groups";
/// HMAC binding the injected identity to a 1-minute window (set by Sluice when GATEWAY_HMAC_KEY
/// is configured). See [`gateway_identity_ok`].
pub const HEADER_SIG: &str = "x-auth-sig";

/// The signed-in user's email, if the gateway injected one. `None` when absent or blank
/// (e.g. a direct dev hit with no gateway in front), letting the caller fall back to a
/// generic label rather than failing the page.
pub fn signed_in_email(headers: &HeaderMap) -> Option<String> {
    headers
        .get(HEADER_EMAIL)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// Admin authorization (X-Auth-Groups) — gates the /ops operator console
// ---------------------------------------------------------------------------

/// Group names that authorize the `/ops` operator console. Membership in ANY of these unlocks
/// the federated read-only console. Same shape as the rest of the estate's admin gate
/// (Relay/Watchtower/Echo `ADMIN_GROUPS`).
pub const ADMIN_GROUPS: &[&str] = &["admins", "infra-admins"];

/// The signed-in user's groups, parsed from the comma-separated `X-Auth-Groups` header. The
/// gateway injects AND HMAC-signs this header (see [`gateway_identity_ok`]), so on the apex
/// route it is trustworthy. Empty when the header is absent/blank.
pub fn author_groups(headers: &HeaderMap) -> Vec<String> {
    header_value(headers, HEADER_GROUPS)
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether the signed-in user belongs to `group` (exact match against `X-Auth-Groups`).
pub fn has_group(headers: &HeaderMap, group: &str) -> bool {
    author_groups(headers).iter().any(|g| g == group)
}

/// Whether the signed-in user is in ANY [`ADMIN_GROUPS`] entry (`X-Auth-Groups` ∩ admin set).
pub fn is_admin(headers: &HeaderMap) -> bool {
    let groups = author_groups(headers);
    ADMIN_GROUPS
        .iter()
        .any(|a| groups.iter().any(|g| g == a))
}

/// Require admin membership for the `/ops` console. `Err(StatusCode::FORBIDDEN)` when the
/// signed-in user carries no admin group — an ordinary user (or an unauthenticated dev hit
/// with no groups) never reaches the console.
pub fn require_admin(headers: &HeaderMap) -> Result<(), axum::http::StatusCode> {
    if is_admin(headers) {
        Ok(())
    } else {
        Err(axum::http::StatusCode::FORBIDDEN)
    }
}

// ---------------------------------------------------------------------------
// Gateway identity signature (X-Auth-Sig) verification
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

/// The shared gateway HMAC key, read once from `GATEWAY_HMAC_KEY`. Empty (unset) disables
/// verification — the pre-signature behavior, fully backward compatible.
fn gateway_key() -> &'static str {
    static KEY: OnceLock<String> = OnceLock::new();
    KEY.get_or_init(|| std::env::var("GATEWAY_HMAC_KEY").unwrap_or_default())
        .as_str()
}

/// Verify the gateway-injected identity is authentic. When `GATEWAY_HMAC_KEY` is set AND an
/// identity (`X-Auth-Subject`) is present, a valid `X-Auth-Sig` — HMAC-SHA256 over
/// `subject "\n" groups "\n" minute` for the current OR previous minute — is REQUIRED; a rogue
/// peer that POSTs `X-Auth-Subject` directly (bypassing Sluice) cannot forge it. Returns:
/// - `true` when the key is unset (verification off), or no identity header is present
///   (public/dev path), or the signature is valid;
/// - `false` when an identity is present but the signature is missing or invalid (=> 401).
pub fn gateway_identity_ok(headers: &HeaderMap) -> bool {
    let key = gateway_key();
    if key.is_empty() {
        return true;
    }
    let Some(subject) = header_value(headers, HEADER_SUBJECT) else {
        return true; // no injected identity to verify (public route / local dev)
    };
    let groups = header_value(headers, HEADER_GROUPS).unwrap_or_default();
    let Some(sig) = header_value(headers, HEADER_SIG) else {
        return false; // identity present but unsigned — reject
    };
    let win = now_unix() / 60;
    // Accept the current and previous minute (clock skew + minute-boundary tolerance).
    [win, win - 1]
        .iter()
        .any(|&w| ct_eq(sig.as_bytes(), sign_identity(key, &subject, &groups, w).as_bytes()))
}

/// Recompute the gateway signature — byte-identical to Sluice's `auth.SignIdentity` (Go).
fn sign_identity(key: &str, subject: &str, groups: &str, window: i64) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key len");
    mac.update(subject.as_bytes());
    mac.update(b"\n");
    mac.update(groups.as_bytes());
    mac.update(b"\n");
    mac.update(window.to_string().as_bytes());
    to_hex(&mac.finalize().into_bytes())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Length-checked constant-time byte comparison (no early return on the first differing byte).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn sign_identity_matches_go_vector() {
        // MUST equal sluice/internal/auth/sig_test.go — the cross-language contract.
        assert_eq!(
            sign_identity("test-key", "usr_alice", "admins,devs", 1),
            "ddc77236dcfb03dd9f462f7c84e1b25e58f5fc380997695a689e6c3ac4bb3777"
        );
        assert_eq!(
            sign_identity("test-key", "usr_bob", "", 2),
            "930f82fb1224e69c9c5bc46e545c3b108b1eeb6c9078c7a33fc24f30c595f658"
        );
    }

    #[test]
    fn gateway_ok_when_key_unset() {
        // No GATEWAY_HMAC_KEY in the test env => verification disabled => always ok.
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUBJECT, HeaderValue::from_static("user-42"));
        assert!(gateway_identity_ok(&h));
    }

    #[test]
    fn admin_gate_over_groups() {
        // No X-Auth-Groups -> no groups, not an admin, require_admin rejects.
        let none = HeaderMap::new();
        assert!(author_groups(&none).is_empty());
        assert!(!has_group(&none, "admins"));
        assert!(!is_admin(&none));
        assert!(require_admin(&none).is_err());

        // Comma-separated groups (with whitespace) parse and match by exact name; either admin
        // group authorizes the console.
        let mut infra = HeaderMap::new();
        infra.insert(HEADER_GROUPS, HeaderValue::from_static("dev, infra-admins ,x"));
        assert!(has_group(&infra, "infra-admins"));
        assert!(has_group(&infra, "dev"));
        assert!(!has_group(&infra, "admins"));
        assert!(is_admin(&infra));
        assert!(require_admin(&infra).is_ok());

        let mut plain = HeaderMap::new();
        plain.insert(HEADER_GROUPS, HeaderValue::from_static("admins"));
        assert!(is_admin(&plain));

        // A non-admin group alone never authorizes.
        let mut other = HeaderMap::new();
        other.insert(HEADER_GROUPS, HeaderValue::from_static("readers,writers"));
        assert!(!is_admin(&other));
        assert_eq!(require_admin(&other), Err(axum::http::StatusCode::FORBIDDEN));
    }
}
