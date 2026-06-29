//! Gateway-injected identity.
//!
//! Portal does NO login of its own. It sits behind a Sluice `auth=sso` route on the apex
//! host `w33d.xyz`, where the gateway runs the OIDC browser login against Keystone, STRIPS
//! any inbound `X-Auth-*`, and injects the verified `X-Auth-Subject` / `X-Auth-Email`.
//! Because Portal is internal-only (never publicly reachable except through Sluice), it
//! TRUSTS the injected `X-Auth-Email` as the signed-in user.

use axum::http::HeaderMap;

pub const HEADER_EMAIL: &str = "x-auth-email";

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
