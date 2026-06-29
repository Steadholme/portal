//! Service catalog: the config-driven list of tiles the dashboard renders.
//!
//! Each [`CatalogEntry`] is one tile — a name, its public subdomain URL, a one-line
//! description, an `icon` key selecting an inline SVG, and the Beacon `component` name the
//! live status pill is derived from. `coming_soon` marks a not-yet-live service (Mail /
//! Corvid): its tile renders a "Coming soon" tag instead of a live status pill.
//!
//! The built-in [`default_catalog`] is the sensible HOLDFAST default; an operator overrides
//! the whole list via the `PORTAL_CATALOG` JSON env var (parsed by [`parse_catalog`]).

use serde::{Deserialize, Serialize};

/// One dashboard tile. Field names match the `PORTAL_CATALOG` JSON override.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CatalogEntry {
    /// Display name (e.g. "Identity").
    pub name: String,
    /// The service's public subdomain the tile links to (e.g. `https://id.w33d.xyz`).
    pub url: String,
    /// One-line description shown under the name.
    #[serde(default)]
    pub description: String,
    /// Beacon component name whose live status drives this tile's pill. Empty (or a name
    /// Beacon does not report) renders an "unknown" pill.
    #[serde(default)]
    pub component: String,
    /// Inline-SVG icon key (see `handlers::icon_svg`); falls back to a generic glyph.
    #[serde(default)]
    pub icon: String,
    /// Mark a not-yet-live service: render a "Coming soon" tag instead of a live pill.
    #[serde(default)]
    pub coming_soon: bool,
}

/// The built-in HOLDFAST service catalog: Identity, Status, Vitals, Audit, and the
/// reserved-for-Corvid Mail tile (coming soon). Each maps to a Beacon component name for its
/// live status; an operator overrides the whole list via `PORTAL_CATALOG`.
pub fn default_catalog() -> Vec<CatalogEntry> {
    vec![
        CatalogEntry {
            name: "Identity".to_string(),
            url: "https://id.w33d.xyz".to_string(),
            description: "Single sign-on, passkeys, and the OIDC issuer.".to_string(),
            component: "Identity".to_string(),
            icon: "identity".to_string(),
            coming_soon: false,
        },
        CatalogEntry {
            name: "Status".to_string(),
            url: "https://status.w33d.xyz".to_string(),
            description: "Live availability and incident history.".to_string(),
            component: "Gateway".to_string(),
            icon: "status".to_string(),
            coming_soon: false,
        },
        CatalogEntry {
            name: "Vitals".to_string(),
            url: "https://vitals.w33d.xyz".to_string(),
            description: "Host metrics and system health dashboards.".to_string(),
            component: "Vitals".to_string(),
            icon: "vitals".to_string(),
            coming_soon: false,
        },
        CatalogEntry {
            name: "Audit".to_string(),
            url: "https://audit.w33d.xyz".to_string(),
            description: "Tamper-evident security audit trail.".to_string(),
            component: "Audit".to_string(),
            icon: "audit".to_string(),
            coming_soon: false,
        },
        CatalogEntry {
            name: "Mail".to_string(),
            url: "https://mail.w33d.xyz".to_string(),
            description: "Secure mail and messaging (Corvid).".to_string(),
            component: "Mail".to_string(),
            icon: "mail".to_string(),
            coming_soon: true,
        },
    ]
}

/// Parse a `PORTAL_CATALOG` JSON array (`[{"name","url","description"?,"component"?,
/// "icon"?,"coming_soon"?}, ...]`).
pub fn parse_catalog(raw: &str) -> Result<Vec<CatalogEntry>, serde_json::Error> {
    serde_json::from_str(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_catalog_has_the_five_holdfast_services() {
        let cat = default_catalog();
        assert_eq!(cat.len(), 5);

        let identity = cat.iter().find(|e| e.name == "Identity").expect("Identity tile");
        assert_eq!(identity.url, "https://id.w33d.xyz");
        assert_eq!(identity.component, "Identity");
        assert!(!identity.coming_soon);

        let mail = cat.iter().find(|e| e.name == "Mail").expect("Mail tile");
        assert_eq!(mail.url, "https://mail.w33d.xyz");
        assert!(mail.coming_soon, "Mail is reserved for Corvid — coming soon");

        for name in ["Status", "Vitals", "Audit"] {
            assert!(cat.iter().any(|e| e.name == name), "{name} tile present");
        }
    }

    #[test]
    fn parse_catalog_reads_override_and_defaults_optional_fields() {
        let raw = r#"[
            {"name":"Alpha","url":"https://a.example","component":"A"},
            {"name":"Beta","url":"https://b.example","description":"d","icon":"mail","coming_soon":true}
        ]"#;
        let cat = parse_catalog(raw).expect("valid catalog JSON");
        assert_eq!(cat.len(), 2);
        // Optional fields default cleanly when omitted.
        assert_eq!(cat[0].description, "");
        assert_eq!(cat[0].icon, "");
        assert!(!cat[0].coming_soon);
        assert_eq!(cat[1].icon, "mail");
        assert!(cat[1].coming_soon);
    }

    #[test]
    fn parse_catalog_rejects_garbage() {
        assert!(parse_catalog("not json").is_err());
    }
}
