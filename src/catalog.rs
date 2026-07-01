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
        name: name.to_string(),
        url: url.to_string(),
        description: description.to_string(),
        component: component.to_string(),
        icon: icon.to_string(),
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
        // --- Developer ---
        e("Git", "https://git.w33d.xyz", "Self-hosted git forge with issues and pull requests.", "Git", "git"),
        e("Registry", "https://registry.w33d.xyz", "OCI/Docker container registry.", "Registry", "registry"),
        // --- Platform ---
        e("Identity", "https://sso.w33d.xyz", "Single sign-on, passkeys and account.", "Identity", "identity"),
        e("Status", "https://status.w33d.xyz", "Live service status and uptime.", "Gateway", "status"),
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
    fn default_catalog_is_public_apps_only() {
        let cat = default_catalog();
        assert_eq!(cat.len(), 21, "curated public app catalog");

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
            "Git", "Registry",
        ] {
            assert!(cat.iter().any(|e| e.name == name), "{name} tile present");
        }

        // VPN-only mgmt surfaces must NOT be advertised on the public apex.
        for host in [
            "vault", "audit", "vitals", "backup", "rca", "traces", "ci", "atlas", "guard", "mesh",
            "spiffe", "deploy", "egress", "purple", "logs", "dns", "people", "authz", "risk",
            "intel", "canary", "edge", "events", "jobs",
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
