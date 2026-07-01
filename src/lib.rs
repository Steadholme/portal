//! Portal — the HOLDFAST apex launcher/dashboard for the sovereign-infra stack.
//!
//! Portal is the dashboard at `w33d.xyz`, fronted by the Sluice gateway on an `auth=sso`
//! route. It does NO login of its own: it reads the gateway-injected `X-Auth-Email` and
//! renders a responsive grid of service tiles, each linking to a public subdomain with a
//! LIVE status pill sourced from Beacon. Integration tests consume [`app`] directly via
//! `tower::oneshot`, exactly like keystone/keyward/beacon.
//!
//! Endpoints:
//! - `GET /`         the dashboard (SSO-fronted; reads `X-Auth-Email`)
//! - `GET /ops`      the admin-gated read-only operator console (`X-Auth-Groups` ∩ admins)
//! - `GET /healthz`  liveness (public; used by the container HEALTHCHECK)

pub mod auth;
pub mod beacon;
pub mod catalog;
pub mod config;
pub mod handlers;
pub mod http;
pub mod snapshot;
pub mod vitals;
pub mod watchtower;

use std::sync::Arc;

use axum::routing::get;
use axum::Router;

use crate::config::Config;
use crate::snapshot::{SnapshotCache, CACHE_TTL};

/// Shared application state. Cheap to clone (everything behind `Arc`). Portal holds no
/// persistent store — only the immutable [`Config`] and the few-second live-data snapshot
/// cache (Beacon statuses + Vitals gauges + Watchtower audit summary, fetched concurrently).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub cache: SnapshotCache,
}

/// Build the router wiring all endpoints onto `state`.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(handlers::dashboard::dashboard))
        .route("/ops", get(handlers::ops::ops))
        .route("/healthz", get(handlers::health::healthz))
        // Reject a forged gateway identity (spoofed X-Auth-* from a rogue in-network peer):
        // when GATEWAY_HMAC_KEY is set, an injected identity MUST carry a valid X-Auth-Sig.
        // No-op when the key is unset or no identity is present (healthz / dev).
        .layer(axum::middleware::from_fn(require_gateway_sig))
        .with_state(state)
}

/// Middleware enforcing [`auth::gateway_identity_ok`] — 401 on a missing/invalid signature.
async fn require_gateway_sig(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if auth::gateway_identity_ok(req.headers()) {
        next.run(req).await
    } else {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid or missing gateway identity signature",
        )
            .into_response()
    }
}

/// Construct dev state: dev [`Config`] (default catalog + default Beacon URL) and a fresh
/// status cache. Used by `main`'s default path and by the integration tests, so they need
/// neither configuration nor a database.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        cache: SnapshotCache::new(CACHE_TTL),
    }
}

/// Build runtime state from the environment. [`Config`] comes from [`Config::from_env`]
/// (env overrides for `BIND_ADDR` / `BEACON_URL` / `PORTAL_CATALOG`). Async only to match
/// the rest of the stack's `main` seam; Portal does no startup IO so it cannot fail.
pub async fn build_state_from_env() -> Result<AppState, String> {
    Ok(AppState {
        config: Arc::new(Config::from_env()),
        cache: SnapshotCache::new(CACHE_TTL),
    })
}
