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
/// Gateway-attested network plane and its independent minute-window HMAC.
pub const HEADER_GATEWAY_ZONE: &str = "x-gateway-zone";
pub const HEADER_GATEWAY_ZONE_SIG: &str = "x-gateway-zone-sig";
pub const GATEWAY_ZONE_INTERNAL: &str = "internal";
pub const DEFAULT_CANONICAL_ROUTE: &str = "portal-root";
pub const DEFAULT_CANONICAL_HOST: &str = "w33d.xyz";

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
// Gateway network-zone signature — gates Estate's internal projection
// ---------------------------------------------------------------------------

/// Verifies Sluice's independent `X-Gateway-Zone-Sig` attestation without exposing the shared
/// key through `Debug`. An empty key preserves local-development compatibility: the exact
/// `internal` zone is accepted without a signature. Production loads the same non-empty
/// independent `GATEWAY_ZONE_HMAC_KEY`; it is never shared with identity signing.
#[derive(Clone)]
pub struct GatewayZoneVerifier {
    key: String,
    expected_route: String,
    expected_host: String,
}

impl Default for GatewayZoneVerifier {
    fn default() -> Self {
        Self::new("")
    }
}

impl std::fmt::Debug for GatewayZoneVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayZoneVerifier")
            .field("enabled", &!self.key.is_empty())
            .field("expected_route", &self.expected_route)
            .field("expected_host", &self.expected_host)
            .finish()
    }
}

impl GatewayZoneVerifier {
    pub fn new(key: impl Into<String>) -> Self {
        Self::with_route_host(key, DEFAULT_CANONICAL_ROUTE, DEFAULT_CANONICAL_HOST)
    }

    fn with_route_host(
        key: impl Into<String>,
        expected_route: impl Into<String>,
        expected_host: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            expected_route: expected_route.into(),
            expected_host: expected_host.into(),
        }
    }

    /// True only for the exact internal zone and, when verification is enabled, a valid HMAC for
    /// the current or previous epoch minute. Invalid/missing attestations downgrade to the public
    /// projection; they never produce an error page or reveal Estate-only entries.
    pub fn is_internal(&self, headers: &HeaderMap) -> bool {
        gateway_zone_internal_with(
            &self.key,
            &self.expected_route,
            &self.expected_host,
            headers,
            now_unix() / 60,
        )
    }
}

fn gateway_zone_internal_with(
    key: &str,
    expected_route: &str,
    expected_host: &str,
    headers: &HeaderMap,
    window: i64,
) -> bool {
    let Some(zone) = header_value(headers, HEADER_GATEWAY_ZONE) else {
        return false;
    };
    if zone != GATEWAY_ZONE_INTERNAL {
        return false;
    }
    if key.is_empty() {
        return true;
    }
    if !header_value(headers, "host").is_some_and(|host| host.eq_ignore_ascii_case(expected_host)) {
        return false;
    }
    let Some(sig) = header_value(headers, HEADER_GATEWAY_ZONE_SIG) else {
        return false;
    };
    [window, window - 1].iter().any(|&candidate| {
        ct_eq(
            sig.as_bytes(),
            sign_gateway_zone(key, expected_route, expected_host, &zone, candidate).as_bytes(),
        )
    })
}

fn sign_gateway_zone(key: &str, route: &str, host: &str, zone: &str, window: i64) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key len");
    mac.update(b"holdfast.gateway-zone.v1\n");
    mac.update(route.as_bytes());
    mac.update(b"\n");
    mac.update(host.as_bytes());
    mac.update(b"\n");
    mac.update(zone.as_bytes());
    mac.update(b"\n");
    mac.update(window.to_string().as_bytes());
    to_hex(&mac.finalize().into_bytes())
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

/// Verify the gateway-injected identity is authentic. When `GATEWAY_HMAC_KEY` is set AND ANY
/// gateway identity header (`X-Auth-Subject` / `X-Auth-Groups` / `X-Auth-Email`) is present, a
/// valid `X-Auth-Sig` — HMAC-SHA256 over `subject "\n" groups "\n" minute` for the current OR
/// previous minute — is REQUIRED. Absent fields hash as the empty string; since Sluice always
/// injects `X-Auth-Subject` together with `X-Auth-Groups`, a rogue peer that POSTs only
/// `X-Auth-Groups: admins` (no subject, no sig) to reach `/ops` cannot produce a matching
/// signature and is rejected. Returns:
/// - `true` when the key is unset (verification off), or NO identity header is present
///   (public/healthz/dev path), or the signature is valid;
/// - `false` when any identity header is present but the signature is missing or invalid (=> 401).
pub fn gateway_identity_ok(headers: &HeaderMap) -> bool {
    gateway_identity_ok_with(gateway_key(), headers)
}

/// Core verification, parameterized on `key` so tests can exercise the key-set branches without
/// touching the process-global `GATEWAY_HMAC_KEY` ([`gateway_key`]'s `OnceLock`).
fn gateway_identity_ok_with(key: &str, headers: &HeaderMap) -> bool {
    if key.is_empty() {
        return true; // verification disabled (no GATEWAY_HMAC_KEY) — pre-signature behavior
    }
    let subject = header_value(headers, HEADER_SUBJECT).unwrap_or_default();
    let groups = header_value(headers, HEADER_GROUPS).unwrap_or_default();
    let has_email = header_value(headers, HEADER_EMAIL).is_some();
    if subject.is_empty() && groups.is_empty() && !has_email {
        return true; // no injected identity to verify (public route / healthz / local dev)
    }
    // An identity header is present => a valid signature is mandatory. The MAC covers
    // `subject "\n" groups "\n" minute`; omitting the subject does not help an attacker because
    // Sluice signs subject + groups together, so a groups-only forgery cannot match.
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
    fn gateway_rejects_groups_only_forgery() {
        // C5 regression: with the key set, a forged `X-Auth-Groups: admins` carrying NO subject
        // and NO signature must be REJECTED — otherwise it would sail through to the /ops admin
        // gate (which only reads groups). Pre-fix this returned true (fail-open on missing subject).
        let mut h = HeaderMap::new();
        h.insert(HEADER_GROUPS, HeaderValue::from_static("admins"));
        assert!(!gateway_identity_ok_with("test-key", &h));
    }

    #[test]
    fn gateway_rejects_identity_without_sig() {
        // Subject + groups present but unsigned => reject.
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUBJECT, HeaderValue::from_static("usr_eve"));
        h.insert(HEADER_GROUPS, HeaderValue::from_static("admins"));
        assert!(!gateway_identity_ok_with("test-key", &h));
    }

    #[test]
    fn gateway_accepts_valid_signature() {
        // A genuinely gateway-signed identity (current minute window) is accepted.
        let (subject, groups) = ("usr_alice", "admins");
        let win = now_unix() / 60;
        let sig = sign_identity("test-key", subject, groups, win);
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUBJECT, HeaderValue::from_str(subject).unwrap());
        h.insert(HEADER_GROUPS, HeaderValue::from_str(groups).unwrap());
        h.insert(HEADER_SIG, HeaderValue::from_str(&sig).unwrap());
        assert!(gateway_identity_ok_with("test-key", &h));
    }

    #[test]
    fn gateway_zone_signature_matches_sluice_vector() {
        assert_eq!(
            sign_gateway_zone("test-key", "portal-root", "w33d.xyz", "internal", 1),
            "3467eb3d618ce5a1d3a0c703f78f3f89f3fb5d80586b78a258fb07352b53f4e3"
        );
    }

    #[test]
    fn internal_zone_requires_valid_current_or_previous_signature() {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_GATEWAY_ZONE, HeaderValue::from_static("internal"));

        assert!(gateway_zone_internal_with(
            "",
            "portal-root",
            "w33d.xyz",
            &headers,
            10
        ));
        assert!(!gateway_zone_internal_with(
            "test-key",
            "portal-root",
            "w33d.xyz",
            &headers,
            10
        ));
        headers.insert("host", HeaderValue::from_static("w33d.xyz"));

        headers.insert(
            HEADER_GATEWAY_ZONE_SIG,
            HeaderValue::from_static("not-a-valid-signature"),
        );
        assert!(!gateway_zone_internal_with(
            "test-key",
            "portal-root",
            "w33d.xyz",
            &headers,
            10
        ));

        let current = sign_gateway_zone("test-key", "portal-root", "w33d.xyz", "internal", 10);
        headers.insert(
            HEADER_GATEWAY_ZONE_SIG,
            HeaderValue::from_str(&current).unwrap(),
        );
        assert!(gateway_zone_internal_with(
            "test-key",
            "portal-root",
            "w33d.xyz",
            &headers,
            10
        ));

        let previous = sign_gateway_zone("test-key", "portal-root", "w33d.xyz", "internal", 9);
        headers.insert(
            HEADER_GATEWAY_ZONE_SIG,
            HeaderValue::from_str(&previous).unwrap(),
        );
        assert!(gateway_zone_internal_with(
            "test-key",
            "portal-root",
            "w33d.xyz",
            &headers,
            10
        ));

        let wrong_route = sign_gateway_zone("test-key", "other-route", "w33d.xyz", "internal", 10);
        headers.insert(
            HEADER_GATEWAY_ZONE_SIG,
            HeaderValue::from_str(&wrong_route).unwrap(),
        );
        assert!(!gateway_zone_internal_with(
            "test-key",
            "portal-root",
            "w33d.xyz",
            &headers,
            10
        ));

        headers.insert("host", HeaderValue::from_static("evil.example"));
        assert!(!gateway_zone_internal_with(
            "test-key",
            "portal-root",
            "w33d.xyz",
            &headers,
            10
        ));

        headers.insert(HEADER_GATEWAY_ZONE, HeaderValue::from_static("external"));
        assert!(!gateway_zone_internal_with(
            "test-key",
            "portal-root",
            "w33d.xyz",
            &headers,
            10
        ));
    }

    #[test]
    fn gateway_ok_no_identity_headers_even_with_key() {
        // Public/healthz path: no X-Auth-* at all => nothing to verify, ok even with key set.
        assert!(gateway_identity_ok_with("test-key", &HeaderMap::new()));
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
