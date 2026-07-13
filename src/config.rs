//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! dev path boots with NO configuration and NO database — exactly like keystone/keyward/
//! beacon. Portal holds no persistent state of its own. Production overrides each via the
//! environment.

use crate::auth::GatewayZoneVerifier;
use crate::catalog::{default_catalog, mgmt_catalog, parse_catalog, CatalogEntry};
use crate::manifest::{load_projection_pair, ProjectionIdentity};

/// Default listen address (all interfaces, internal-only port 8600).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8600";
/// Default PUBLIC Beacon projection base URL. External dashboard responses append
/// `/api/status` and may only render this deliberately reduced component snapshot.
pub const DEFAULT_BEACON_PUBLIC_URL: &str = "http://beacon:8400";
/// Default INTERNAL/operator Beacon base URL. Internal Estate and `/ops` responses append
/// `/api/status` to fetch the full component snapshot over the `holdfast` Docker network.
pub const DEFAULT_BEACON_URL: &str = "http://beacon:8401";
/// Default INTERNAL Vitals base URL. The metric cards append `/api/metrics` for the latest
/// host CPU / memory / load gauges.
pub const DEFAULT_VITALS_URL: &str = "http://vitals:8300";
/// Default INTERNAL Watchtower base URL. The audit card appends `/api/verify` (chain count +
/// integrity) and the activity feed appends `/api/events`.
pub const DEFAULT_WATCHTOWER_URL: &str = "http://watchtower:8500";
pub const EXPERIENCE_PUBLIC_PROJECTION: &str = "EXPERIENCE_PUBLIC_PROJECTION";
pub const EXPERIENCE_ESTATE_PROJECTION: &str = "EXPERIENCE_ESTATE_PROJECTION";

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// PUBLIC Beacon projection base URL (`BEACON_PUBLIC_URL`); external live-status rendering
    /// hits `<url>/api/status` and never reads the operator snapshot.
    pub beacon_public_url: String,
    /// INTERNAL/operator Beacon base URL (`BEACON_URL`); Estate and `/ops` live-status rendering
    /// hits `<url>/api/status`.
    pub beacon_url: String,
    /// INTERNAL Vitals base URL (`VITALS_URL`); the metric cards hit `<url>/api/metrics`.
    pub vitals_url: String,
    /// INTERNAL Watchtower base URL (`WATCHTOWER_URL`); the audit card hits `<url>/api/verify`
    /// and the activity feed hits `<url>/api/events`.
    pub watchtower_url: String,
    /// Service tiles rendered on the dashboard (`PORTAL_CATALOG` JSON override, else the
    /// built-in HOLDFAST default).
    pub catalog: Vec<CatalogEntry>,
    /// Additional Estate-only tiles. The dashboard reads this slice only after a valid internal
    /// gateway-zone attestation; external responses never render or serialize it.
    pub internal_catalog: Vec<CatalogEntry>,
    /// Audience-specific identities shown by the Estate Manifest signal.
    pub public_projection: Option<ProjectionIdentity>,
    pub estate_projection: Option<ProjectionIdentity>,
    /// Verifier for Sluice's independently signed network-zone attestation.
    pub zone_verifier: GatewayZoneVerifier,
}

impl Config {
    /// Default development configuration (separate Beacon projections + default catalogs).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            beacon_public_url: DEFAULT_BEACON_PUBLIC_URL.to_string(),
            beacon_url: DEFAULT_BEACON_URL.to_string(),
            vitals_url: DEFAULT_VITALS_URL.to_string(),
            watchtower_url: DEFAULT_WATCHTOWER_URL.to_string(),
            catalog: default_catalog(),
            internal_catalog: mgmt_catalog(),
            public_projection: None,
            estate_projection: None,
            zone_verifier: GatewayZoneVerifier::default(),
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Result<Self, String> {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("BEACON_PUBLIC_URL") {
            config.beacon_public_url = v;
        }
        if let Some(v) = env_nonempty("BEACON_URL") {
            config.beacon_url = v;
        }
        if let Some(v) = env_nonempty("VITALS_URL") {
            config.vitals_url = v;
        }
        if let Some(v) = env_nonempty("WATCHTOWER_URL") {
            config.watchtower_url = v;
        }
        let gateway_zone_hmac_key = std::env::var("GATEWAY_ZONE_HMAC_KEY").unwrap_or_default();
        let gateway_identity_hmac_key = std::env::var("GATEWAY_HMAC_KEY").unwrap_or_default();
        config.zone_verifier = GatewayZoneVerifier::new(gateway_zone_hmac_key.clone());

        let public_path = env_nonempty(EXPERIENCE_PUBLIC_PROJECTION);
        let estate_path = env_nonempty(EXPERIENCE_ESTATE_PROJECTION);
        let projections_loaded = load_projection_paths(
            &mut config,
            public_path.as_deref(),
            estate_path.as_deref(),
            &gateway_zone_hmac_key,
            &gateway_identity_hmac_key,
        )?;

        if !projections_loaded {
            apply_legacy_catalog(&mut config);
        } else if env_nonempty("PORTAL_CATALOG").is_some() {
            tracing::warn!("PORTAL_CATALOG is ignored while Experience projections are configured");
        }
        Ok(config)
    }
}

fn load_projection_paths(
    config: &mut Config,
    public_path: Option<&str>,
    estate_path: Option<&str>,
    gateway_zone_hmac_key: &str,
    gateway_identity_hmac_key: &str,
) -> Result<bool, String> {
    match (public_path, estate_path) {
        (None, None) => Ok(false),
        (Some(public), Some(estate)) => {
            if gateway_zone_hmac_key.is_empty() {
                return Err(
                    "GATEWAY_ZONE_HMAC_KEY must be non-empty when Experience projections are configured"
                        .to_string(),
                );
            }
            if gateway_zone_hmac_key == gateway_identity_hmac_key {
                return Err(
                    "GATEWAY_ZONE_HMAC_KEY must be distinct from GATEWAY_HMAC_KEY".to_string(),
                );
            }
            let pair = load_projection_pair(public, estate).map_err(|error| error.to_string())?;
            config.catalog = pair.public.catalog;
            config.internal_catalog = pair.estate.catalog;
            config.public_projection = Some(pair.public.identity);
            config.estate_projection = Some(pair.estate.identity);
            Ok(true)
        }
        (Some(_), None) => Err(format!(
            "{EXPERIENCE_ESTATE_PROJECTION} must be set when {EXPERIENCE_PUBLIC_PROJECTION} is set"
        )),
        (None, Some(_)) => Err(format!(
            "{EXPERIENCE_PUBLIC_PROJECTION} must be set when {EXPERIENCE_ESTATE_PROJECTION} is set"
        )),
    }
}

fn apply_legacy_catalog(config: &mut Config) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn projection(audience: &str, id: &str, url: &str) -> String {
        let fingerprint = if audience == "public" {
            "a".repeat(64)
        } else {
            "b".repeat(64)
        };
        format!(
            r#"{{"schemaVersion":"holdfast.experience-projection.v1","release":"1.0.0","fingerprint":"sha256:{fingerprint}","audience":"{audience}","surfaces":[{{"id":"{id}","name":"{id}","description":"A product surface","url":"{url}","category":"platform","icon":"grid","statusComponent":"Example","profile":"control","capabilities":[],"comingSoon":false}}]}}"#
        )
    }

    #[test]
    fn beacon_scope_defaults_are_distinct() {
        let config = Config::dev();
        assert_eq!(config.beacon_public_url, "http://beacon:8400");
        assert_eq!(config.beacon_url, "http://beacon:8401");
        assert_ne!(config.beacon_public_url, config.beacon_url);
    }

    fn temp_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "portal-projection-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn projection_paths_must_be_paired_and_production_requires_hmac_key() {
        let mut config = Config::dev();
        let error = load_projection_paths(
            &mut config,
            Some("public.json"),
            None,
            "zone-key",
            "identity-key",
        )
        .unwrap_err();
        assert!(error.contains(EXPERIENCE_ESTATE_PROJECTION));

        let error = load_projection_paths(
            &mut config,
            Some("public.json"),
            Some("estate.json"),
            "",
            "identity-key",
        )
        .unwrap_err();
        assert!(error.contains("GATEWAY_ZONE_HMAC_KEY must be non-empty"));

        let error = load_projection_paths(
            &mut config,
            Some("public.json"),
            Some("estate.json"),
            "shared-key",
            "shared-key",
        )
        .unwrap_err();
        assert!(error.contains("must be distinct from GATEWAY_HMAC_KEY"));
    }

    #[test]
    fn startup_loads_valid_pair_and_fails_closed_on_invalid_contract() {
        let dir = temp_dir();
        let public = dir.join("public.json");
        let estate = dir.join("estate.json");
        fs::write(
            &public,
            projection("public", "mail-web", "https://mail.w33d.xyz"),
        )
        .unwrap();
        fs::write(
            &estate,
            projection("estate", "vault-ops", "https://vault.w33d.xyz"),
        )
        .unwrap();

        let mut config = Config::dev();
        assert!(load_projection_paths(
            &mut config,
            public.to_str(),
            estate.to_str(),
            "zone-key",
            "identity-key",
        )
        .unwrap());
        assert_eq!(config.catalog.len(), 1);
        assert_eq!(config.catalog[0].id, "mail-web");
        assert_eq!(config.internal_catalog.len(), 1);
        assert_eq!(config.internal_catalog[0].id, "vault-ops");
        assert_eq!(config.public_projection.as_ref().unwrap().release, "1.0.0");

        fs::write(
            &estate,
            projection("estate", "mail-web", "https://vault.w33d.xyz"),
        )
        .unwrap();
        let mut overlap = Config::dev();
        let error = load_projection_paths(
            &mut overlap,
            public.to_str(),
            estate.to_str(),
            "zone-key",
            "identity-key",
        )
        .unwrap_err();
        assert!(error.contains("occurs in both public and estate projections"));

        let same_fingerprint = projection("estate", "vault-ops", "https://vault.w33d.xyz").replace(
            &format!("sha256:{}", "b".repeat(64)),
            &format!("sha256:{}", "a".repeat(64)),
        );
        fs::write(&estate, same_fingerprint).unwrap();
        let mut identical_identity = Config::dev();
        let error = load_projection_paths(
            &mut identical_identity,
            public.to_str(),
            estate.to_str(),
            "zone-key",
            "identity-key",
        )
        .unwrap_err();
        assert!(error.contains("fingerprints must be distinct"));

        fs::write(
            &estate,
            projection("estate", "vault-ops", "https://mail.w33d.xyz/"),
        )
        .unwrap();
        let mut trailing_slash_alias = Config::dev();
        let error = load_projection_paths(
            &mut trailing_slash_alias,
            public.to_str(),
            estate.to_str(),
            "zone-key",
            "identity-key",
        )
        .unwrap_err();
        assert!(error.contains("root URL must omit the trailing slash"));

        let leaking_public = projection("public", "mail-web", "https://mail.w33d.xyz")
            .replace("A product surface", "Use vault.w33d.xyz for details");
        fs::write(&public, leaking_public).unwrap();
        fs::write(
            &estate,
            projection("estate", "vault-ops", "https://vault.w33d.xyz"),
        )
        .unwrap();
        let mut leaked_host = Config::dev();
        let error = load_projection_paths(
            &mut leaked_host,
            public.to_str(),
            estate.to_str(),
            "zone-key",
            "identity-key",
        )
        .unwrap_err();
        assert!(error.contains("leaks estate host"));

        fs::write(&estate, "{}").unwrap();
        let mut invalid = Config::dev();
        let error = load_projection_paths(
            &mut invalid,
            public.to_str(),
            estate.to_str(),
            "zone-key",
            "identity-key",
        )
        .unwrap_err();
        assert!(error.contains("invalid estate Experience projection JSON"));

        fs::remove_dir_all(dir).unwrap();
    }
}
