//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! dev path boots with NO configuration and NO database — exactly like keystone/keyward/
//! beacon. Portal holds no persistent state of its own. Production overrides each via the
//! environment.

use crate::catalog::{default_catalog, parse_catalog, CatalogEntry};

/// Default listen address (all interfaces, internal-only port 8600).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8600";
/// Default INTERNAL Beacon base URL. The dashboard appends `/api/status` to fetch the live
/// component snapshot over the `holdfast` Docker network.
pub const DEFAULT_BEACON_URL: &str = "http://beacon:8400";

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// INTERNAL Beacon base URL (`BEACON_URL`); the live-status fetch hits `<url>/api/status`.
    pub beacon_url: String,
    /// Service tiles rendered on the dashboard (`PORTAL_CATALOG` JSON override, else the
    /// built-in HOLDFAST default).
    pub catalog: Vec<CatalogEntry>,
}

impl Config {
    /// Default development configuration (default Beacon URL + default catalog).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            beacon_url: DEFAULT_BEACON_URL.to_string(),
            catalog: default_catalog(),
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("BEACON_URL") {
            config.beacon_url = v;
        }
        if let Some(raw) = env_nonempty("PORTAL_CATALOG") {
            match parse_catalog(&raw) {
                Ok(cat) if !cat.is_empty() => config.catalog = cat,
                Ok(_) => {
                    tracing::warn!("PORTAL_CATALOG parsed to an empty list — using default catalog")
                }
                Err(e) => {
                    tracing::warn!(error = %e, "PORTAL_CATALOG is not valid JSON — using default catalog")
                }
            }
        }
        config
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// Read an env var, returning `None` when unset OR empty (empty never clobbers a default).
fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}
