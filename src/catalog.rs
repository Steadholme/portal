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
    /// Stable product/surface identity from Experience Manifest. Legacy `PORTAL_CATALOG`
    /// entries may omit it; the renderer then keeps the URL-only app identity behavior.
    #[serde(default)]
    pub id: String,
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
    /// Canonical Experience category. Empty keeps the legacy name-based grouping fallback.
    #[serde(default)]
    pub category: String,
    /// Odyssey presentation profile selected by the canonical Manifest projection.
    #[serde(default)]
    pub profile: String,
    /// Sorted declarative capability labels. Retained for inspection; Portal does not derive
    /// behavior or authorization from them.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Mark a not-yet-live service: render a "Coming soon" tag instead of a live pill.
    #[serde(default)]
    pub coming_soon: bool,
}

/// The built-in HOLDFAST **public** apex catalog: only the user-facing app surfaces that are
/// actually reachable through the public gateway. Ops/mgmt surfaces (Vitals, Audit, Vault,
/// Backup, CI, DNS, …) are deliberately EXCLUDED — post network-zoning they are VPN-only and
/// return 404 to the public, so they never belong on a public launcher. Each tile maps to a
/// Beacon component name (mirrors the deploy's `BEACON_SEED`) so the live status pill resolves.
///
/// The list is curated from a per-service audit of the real product surface (every entry below
/// is a verified working feature, not a routed placeholder). An operator may still override the
/// whole list via `PORTAL_CATALOG`.
pub fn default_catalog() -> Vec<CatalogEntry> {
    // (name, url, description, beacon component, icon key)
    let e = |name: &str, url: &str, description: &str, component: &str, icon: &str| CatalogEntry {
        id: default_id(url),
        name: name.to_string(),
        url: url.to_string(),
        description: description.to_string(),
        component: component.to_string(),
        icon: icon.to_string(),
        category: String::new(),
        profile: String::new(),
        capabilities: Vec::new(),
        coming_soon: false,
    };
    vec![
        // --- Communication ---
        e("Mail", "https://mail.w33d.xyz", "SSO webmail — inbox, compose and send DKIM-signed mail.", "Mail", "mail"),
        e("Chat", "https://chat.w33d.xyz", "Real-time team chat with rooms and a live feed.", "Chat", "chat"),
        e("Notifications", "https://notify.w33d.xyz", "Notification inbox with mark-read and a live stream.", "Notify", "bell"),
        e("Inbox", "https://inbox.w33d.xyz", "Unified inbox — unread chat, notifications and feeds.", "Inbox", "inbox"),
        e("Calendar", "https://cal.w33d.xyz", "Personal calendar and address book.", "Calendar", "calendar"),
        // --- Content & publishing ---
        e("Blog", "https://blog.w33d.xyz", "Markdown blog/CMS with an \u{201c}ask your blog\u{201d} Q&A.", "Blog", "blog"),
        e("Forum", "https://forum.w33d.xyz", "Discussion forum — categories, threads and replies.", "Forum", "forum"),
        e("Wiki", "https://wiki.w33d.xyz", "Knowledge-base wiki with revision history.", "Wiki", "wiki"),
        e("Comments", "https://comments.w33d.xyz", "Embeddable threaded comments with moderation.", "Comments", "comments"),
        e("Paste", "https://paste.w33d.xyz", "Pastebin with expiry and burn-after-read snippets.", "Pastefire", "paste"),
        e("Drive", "https://drive.w33d.xyz", "Image/file host with unguessable share links.", "Drive", "drive"),
        // --- Reading ---
        e("Feeds", "https://rss.w33d.xyz", "RSS/Atom river reader with local TL;DRs.", "Feeds", "rss"),
        e("Clips", "https://clip.w33d.xyz", "Read-it-later clipper with a clean reader view.", "Clips", "clip"),
        e("Social", "https://social.w33d.xyz", "Single-user ActivityPub microblog.", "Social", "social"),
        // --- Knowledge & AI ---
        e("Search", "https://search.w33d.xyz", "Federated search with cited Q&A across your content.", "Search", "search"),
        e("Assistant", "https://ami.w33d.xyz", "Personal AI chat plus replayable AI workflows.", "Familiar", "assistant"),
        e("AI Gateway", "https://ai.w33d.xyz", "OpenAI-compatible LLM gateway and API-key console.", "Relay", "ai"),
        e("Multica", "https://multica.w33d.xyz", "Managed coding-agent workspace with issues, runtimes and reusable skills.", "Multica", "ai"),
        // --- Developer ---
        e("Git", "https://git.w33d.xyz", "Self-hosted git forge with issues and pull requests.", "Git", "git"),
        e("Registry", "https://registry.w33d.xyz", "OCI/Docker container registry.", "Registry", "registry"),
        // --- Platform ---
        e("Identity", "https://sso.w33d.xyz", "Single sign-on, passkeys and account.", "Identity", "identity"),
        e("Status", "https://status.w33d.xyz", "Live service status and uptime.", "Gateway", "status"),
    ]
}

/// VPN/internal-only management consoles. These are rendered separately from the public
/// [`default_catalog`] and only when the gateway marks the request as internal.
pub fn mgmt_catalog() -> Vec<CatalogEntry> {
    // (name, url, description, beacon component, icon key)
    let e = |name: &str, url: &str, description: &str, component: &str, icon: &str| CatalogEntry {
        id: default_id(url),
        name: name.to_string(),
        url: url.to_string(),
        description: description.to_string(),
        component: component.to_string(),
        icon: icon.to_string(),
        category: String::new(),
        profile: String::new(),
        capabilities: Vec::new(),
        coming_soon: false,
    };
    vec![
        e("Authorization", "https://authz.w33d.xyz", "Policy decisions and service authorization controls.", "Authz", "authz"),
        e("Directory", "https://people.w33d.xyz", "People, groups and account directory controls.", "People", "people"),
        e("Vault", "https://vault.w33d.xyz", "Secrets, leases and encryption policy console.", "Vault", "vault"),
        e("Audit log", "https://audit.w33d.xyz", "Tamper-evident audit search and investigation trail.", "Audit", "audit"),
        e("Vitals", "https://vitals.w33d.xyz", "Host metrics, resource gauges and telemetry drilldown.", "Vitals", "vitals"),
        e("Logs", "https://logs.w33d.xyz", "Centralized logs with search, filters and live tail.", "Sift", "logs"),
        e("Traces", "https://traces.w33d.xyz", "Distributed tracing and request-path diagnostics.", "Filament", "traces"),
        e("DNS", "https://dns.w33d.xyz", "Authoritative DNS zones, records and split-horizon controls.", "Lodestar", "dns"),
        e("Backup", "https://backup.w33d.xyz", "Backup snapshots, retention policy and restore verification.", "Backup", "backup"),
        e("CI", "https://ci.w33d.xyz", "Build pipelines, runs and supply-chain checks.", "Anvil", "ci"),
        e("Deploy", "https://deploy.w33d.xyz", "Release rollout, routing and rollback controls.", "Skiff", "skiff"),
        e("Sites", "https://siteflow.w33d.xyz", "Git-to-deploy site builds, previews and rollbacks.", "SiteFlow", "sites"),
        e("Egress", "https://egress.w33d.xyz", "Outbound proxy policy, reputation and audit controls.", "Estuary", "estuary"),
        e("Mesh", "https://mesh.w33d.xyz", "WireGuard mesh peers, ACLs and device enrollment.", "Mycelium", "mesh"),
        e("Edge", "https://edge.w33d.xyz", "Static edge cache, purge and asset delivery controls.", "Eddy", "edge"),
        e("SPIFFE", "https://spiffe.w33d.xyz", "Workload identity, SVIDs and trust bundle management.", "Sigil", "sigil"),
        e("Risk", "https://risk.w33d.xyz", "Continuous access risk scoring and session signals.", "Pulse", "pulse"),
        e("Events", "https://events.w33d.xyz", "Durable event streams and CDC-backed routing.", "Events", "events"),
        e("Jobs", "https://jobs.w33d.xyz", "Scheduled jobs, queues and worker run history.", "Jobs", "jobs"),
        e("Intel", "https://intel.w33d.xyz", "Threat intel, IOC graph and reputation lookups.", "Intel", "intel"),
        e("Guard", "https://guard.w33d.xyz", "Content moderation, policy scoring and safety verdicts.", "Warden", "guard"),
        e("Purple", "https://purple.w33d.xyz", "Continuous validation of detections and attack simulations.", "Phantom", "phantom"),
        e("Atlas", "https://atlas.w33d.xyz", "Internal developer portal and service catalog.", "Atlas", "atlas"),
        e("RCA", "https://rca.w33d.xyz", "Root-cause investigations across metrics, logs and traces.", "RCA", "rca"),
        e("Detonate", "https://detonate.w33d.xyz", "Sandboxed sample analysis, verdicts and IOC extraction.", "Crucible", "crucible"),
        e("Canary", "https://canary.w33d.xyz", "Canary tokens, honeypots and uptime tripwires.", "Canary", "canary"),
        e("VPN enrollment", "https://vpn.w33d.xyz", "WireGuard credential enrollment and bootstrap access.", "Mycelium", "mesh"),
    ]
}

fn default_id(url: &str) -> String {
    url.strip_prefix("https://")
        .unwrap_or(url)
        .split(['/', '.', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_string()
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
    fn default_catalog_is_public_apps_only() {
        let cat = default_catalog();
        assert_eq!(cat.len(), 22, "curated public app catalog");

        let identity = cat.iter().find(|e| e.name == "Identity").expect("Identity tile");
        assert_eq!(identity.url, "https://sso.w33d.xyz");
        assert_eq!(identity.component, "Identity");

        // Mail (Corvid) is LIVE now — never coming_soon.
        let mail = cat.iter().find(|e| e.name == "Mail").expect("Mail tile");
        assert_eq!(mail.url, "https://mail.w33d.xyz");
        assert!(!mail.coming_soon, "Corvid mail is live");
        assert!(cat.iter().all(|e| !e.coming_soon), "no coming-soon tiles remain");

        // Status maps to Beacon's Gateway component; Paste maps to the Pastefire component.
        assert_eq!(cat.iter().find(|e| e.name == "Status").unwrap().component, "Gateway");
        assert_eq!(cat.iter().find(|e| e.name == "Paste").unwrap().component, "Pastefire");

        // Every real user-facing surface is present.
        for name in [
            "Blog", "Forum", "Wiki", "Comments", "Paste", "Drive", "Feeds", "Clips", "Social",
            "Search", "Assistant", "AI Gateway", "Chat", "Calendar", "Notifications", "Inbox",
            "Multica", "Git", "Registry",
        ] {
            assert!(cat.iter().any(|e| e.name == name), "{name} tile present");
        }

        // VPN-only mgmt surfaces must NOT be advertised on the public apex.
        for host in [
            "vault", "audit", "vitals", "backup", "rca", "traces", "ci", "atlas", "guard", "mesh",
            "spiffe", "deploy", "egress", "purple", "logs", "dns", "people", "authz", "risk",
            "intel", "canary", "edge", "events", "jobs", "detonate", "vpn",
        ] {
            let url = format!("https://{host}.w33d.xyz");
            assert!(
                cat.iter().all(|e| e.url != url),
                "mgmt host {host} must not be a public tile"
            );
        }

        // Every tile carries a non-empty beacon component + icon key so pills/glyphs resolve.
        for e in &cat {
            assert!(!e.component.is_empty(), "{} has a beacon component", e.name);
            assert!(!e.icon.is_empty(), "{} has an icon", e.name);
        }
    }

    #[test]
    fn mgmt_catalog_is_internal_ops_consoles_only() {
        let cat = mgmt_catalog();
        assert_eq!(cat.len(), 27, "curated internal management catalog");

        for (host, name, component) in [
            ("authz", "Authorization", "Authz"),
            ("people", "Directory", "People"),
            ("vault", "Vault", "Vault"),
            ("audit", "Audit log", "Audit"),
            ("vitals", "Vitals", "Vitals"),
            ("logs", "Logs", "Sift"),
            ("traces", "Traces", "Filament"),
            ("dns", "DNS", "Lodestar"),
            ("backup", "Backup", "Backup"),
            ("ci", "CI", "Anvil"),
            ("deploy", "Deploy", "Skiff"),
            ("siteflow", "Sites", "SiteFlow"),
            ("egress", "Egress", "Estuary"),
            ("mesh", "Mesh", "Mycelium"),
            ("edge", "Edge", "Eddy"),
            ("spiffe", "SPIFFE", "Sigil"),
            ("risk", "Risk", "Pulse"),
            ("events", "Events", "Events"),
            ("jobs", "Jobs", "Jobs"),
            ("intel", "Intel", "Intel"),
            ("guard", "Guard", "Warden"),
            ("purple", "Purple", "Phantom"),
            ("atlas", "Atlas", "Atlas"),
            ("rca", "RCA", "RCA"),
            ("detonate", "Detonate", "Crucible"),
            ("canary", "Canary", "Canary"),
            ("vpn", "VPN enrollment", "Mycelium"),
        ] {
            let entry = cat.iter().find(|e| e.url == format!("https://{host}.w33d.xyz"));
            let entry = entry.unwrap_or_else(|| panic!("mgmt host {host} present"));
            assert_eq!(entry.name, name);
            assert_eq!(entry.component, component);
            assert!(!entry.description.is_empty(), "{name} has a description");
            assert!(!entry.icon.is_empty(), "{name} has an icon");
            assert!(!entry.coming_soon, "{name} is live/internal, not coming soon");
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
        assert_eq!(cat[0].id, "");
        assert_eq!(cat[0].description, "");
        assert_eq!(cat[0].icon, "");
        assert_eq!(cat[0].category, "");
        assert_eq!(cat[0].profile, "");
        assert!(cat[0].capabilities.is_empty());
        assert!(!cat[0].coming_soon);
        assert_eq!(cat[1].icon, "mail");
        assert!(cat[1].coming_soon);
    }

    #[test]
    fn parse_catalog_rejects_garbage() {
        assert!(parse_catalog("not json").is_err());
    }
}
