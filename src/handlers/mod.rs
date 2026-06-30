//! HTTP handlers + shared server-render helpers.
//!
//! `health` is the unauthenticated liveness probe; `dashboard` is the SSO-fronted apex
//! launcher. The shared design tokens / CSS are embedded (via `include_str!`) and inlined
//! into the page, matching the HOLDFAST enterprise brand (the same look as the Keystone
//! login UI and the Beacon status page): brand gradient, indigo accent, status pills,
//! cards, app-bar with the shield + wordmark.

pub mod dashboard;
pub mod health;

/// Embedded design system, inlined into the rendered page's `<style>`.
pub const APP_CSS: &str = include_str!("../../static/app.css");

/// The HOLDFAST shield glyph (small, for the app-bar brand lockup). Shared verbatim with
/// the rest of the stack so the whole product reads as one brand.
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="hf-shield-sm" x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse"><stop stop-color="#818CF8"/><stop offset="1" stop-color="#4F46E5"/></linearGradient></defs><path d="M24 4 8 9.5V22c0 11 7 17.4 16 21.5C33 39.4 40 33 40 22V9.5L24 4Z" fill="url(#hf-shield-sm)"/><rect x="20" y="19" width="8" height="13" rx="1" fill="#fff" fill-opacity="0.92"/><path d="M20 19v-2.5a4 4 0 0 1 8 0V19" stroke="#fff" stroke-width="2" stroke-opacity="0.92" fill="none"/></svg>"##;

/// Minimal HTML escaping for text/attribute interpolation.
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Human label for a live status token (Beacon's `operational` | `degraded` | `down`, plus
/// the Portal-only `unknown` for an unreachable Beacon or an unmapped component).
pub fn status_label(status: &str) -> &'static str {
    match status {
        "operational" => "Operational",
        "degraded" => "Degraded",
        "down" => "Down",
        _ => "Unknown",
    }
}

/// CSS modifier class for a status token's pill.
pub fn status_pill_class(status: &str) -> &'static str {
    match status {
        "operational" => "pill-ok",
        "degraded" => "pill-warn",
        "down" => "pill-down",
        _ => "pill-unknown",
    }
}

/// A live status pill (`<span class="pill ...">Label</span>`).
pub fn status_pill(status: &str) -> String {
    format!(
        r#"<span class="pill {cls}">{label}</span>"#,
        cls = status_pill_class(status),
        label = status_label(status),
    )
}

/// The "coming soon" tag shown on a not-yet-live tile in place of a live pill.
pub fn coming_soon_pill() -> String {
    r#"<span class="pill pill-soon">Coming soon</span>"#.to_string()
}

/// Inline-SVG glyph for a catalog `icon` key. Unknown keys fall back to a generic grid
/// glyph, so a misconfigured catalog still renders a sensible tile. All strokes use
/// `currentColor` so the icon inherits the tile accent.
pub fn icon_svg(key: &str) -> &'static str {
    match key {
        "identity" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1"/></svg>"##,
        "status" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l2 6 4-14 2 8h6"/></svg>"##,
        "vitals" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20.8 5.6a5 5 0 0 0-8.8 1.4 5 5 0 0 0-8.8-1.4 5 5 0 0 0 1.3 6L12 20l7.5-8.4a5 5 0 0 0 1.3-6Z"/></svg>"##,
        "audit" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V5l-8-3Z"/><path d="m9 12 2 2 4-4"/></svg>"##,
        "mail" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m4 7 8 6 8-6"/></svg>"##,
        "blog" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h11l5 5v11a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1Z"/><path d="M14 4v5h5"/><path d="M8 13h8M8 17h6"/></svg>"##,
        "forum" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 10h8M8 14h5"/><path d="M21 12a7 7 0 0 1-7 7H8l-4 3v-4.3A7 7 0 0 1 8 5h6a7 7 0 0 1 7 7Z"/></svg>"##,
        "wiki" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 5a2 2 0 0 1 2-2h6v18H6a2 2 0 0 0-2 2V5Z"/><path d="M20 5a2 2 0 0 0-2-2h-6v18h6a2 2 0 0 1 2 2V5Z"/></svg>"##,
        "paste" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="3" width="8" height="4" rx="1"/><path d="M16 5h2a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h2"/><path d="m9 13 2 2 4-4"/></svg>"##,
        "vault" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="12" cy="12" r="3.5"/><path d="M12 12h5"/></svg>"##,
        "intel" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V5l-8-3Z"/><path d="M12 8v4M12 16h.01"/></svg>"##,
        "canary" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 7a3 3 0 1 0-3-3"/><path d="M13 4 4 13l3 3 5-1 4-4a4 4 0 0 0 0-6Z"/><path d="m9 16-2 4"/></svg>"##,
        "drive" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M6 19a4 4 0 0 1-.9-7.9A5 5 0 0 1 15 9a4 4 0 0 1 1 7.9"/><path d="M12 12v6M9 15l3-3 3 3"/></svg>"##,
        "search" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>"##,
        "calendar" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="17" rx="2"/><path d="M3 9h18M8 2v4M16 2v4"/></svg>"##,
        "rss" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 11a9 9 0 0 1 9 9M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1.5"/></svg>"##,
        "clip" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M19 7v10a4 4 0 0 1-8 0V6a2.5 2.5 0 0 1 5 0v9.5a1 1 0 0 1-2 0V7"/></svg>"##,
        "chat" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a8 8 0 0 1-8 8H7l-4 3v-4.5A8 8 0 0 1 13 4a8 8 0 0 1 8 8Z"/><path d="M8 11h.01M12 11h.01M16 11h.01"/></svg>"##,
        "bell" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/></svg>"##,
        "inbox" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h5l2 3h4l2-3h5"/><path d="M5 5h14l2 7v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-5L5 5Z"/></svg>"##,
        "logs" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h16M4 10h10M4 14h16M4 18h7"/></svg>"##,
        "ai" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v2M12 19v2M5 12H3M21 12h-2"/><rect x="6" y="6" width="12" height="12" rx="3"/><path d="M10 10h.01M14 10h.01M9.5 14h5"/></svg>"##,
        "rag" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h11l5 5v11a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1Z"/><path d="M14 4v5h5"/><path d="m9 13 2 2 3-3"/></svg>"##,
        "assistant" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="7" width="16" height="12" rx="3"/><path d="M12 3v4M9 13h.01M15 13h.01"/><path d="M2 12v2M22 12v2"/></svg>"##,
        "git" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="2.5"/><circle cx="6" cy="18" r="2.5"/><circle cx="17" cy="9" r="2.5"/><path d="M6 8.5v7M17 11.5c0 3-4 2.5-8 4"/></svg>"##,
        "registry" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3 8 4.5v9L12 21l-8-4.5v-9L12 3Z"/><path d="m4 7.5 8 4.5 8-4.5M12 12v9"/></svg>"##,
        "dns" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18Z"/></svg>"##,
        "comments" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 10h8M8 13h5"/><path d="M21 11.5a7.5 7.5 0 0 1-11 6.6L3 20l1.9-4.3A7.5 7.5 0 1 1 21 11.5Z"/></svg>"##,
        "people" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="8" r="3.2"/><path d="M3 20v-1a5 5 0 0 1 5-5h2a5 5 0 0 1 5 5v1"/><path d="M16 4a3 3 0 0 1 0 6M18.5 20v-1a4.5 4.5 0 0 0-3-4.2"/></svg>"##,
        "authz" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="m11 12 9-9 1 3 2 1-3 3-3-1-3 3"/></svg>"##,
        "events" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8c4 0 4 8 8 8s4-8 8-8M3 16c4 0 4-8 8-8"/></svg>"##,
        "jobs" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>"##,
        "backup" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg>"##,
        "rca" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l2 7 4-14 2 7h6"/><circle cx="12" cy="12" r="9" opacity="0"/></svg>"##,
        "social" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m3 11 18-7-4 18-5-6-9-5Z"/><path d="m12 16-1 4 3-3"/></svg>"##,
        "cache" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/><path d="m11 10-2 3h3l-2 3"/></svg>"##,
        "edge" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18Z"/><path d="m13 9-3 4h3l-3 4" fill="none"/></svg>"##,
        "traces" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 5h12M4 10h8M4 15h14M4 20h6"/><circle cx="19" cy="5" r="1.6"/><circle cx="14" cy="10" r="1.6"/></svg>"##,
        "ci" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4 4 0 0 0-5.4 5.4l-6 6 2 2 6-6a4 4 0 0 0 5.4-5.4l-2.5 2.5-2-2 2.5-2.5Z"/></svg>"##,
        "atlas" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m9 4 6 2 5-2v14l-5 2-6-2-5 2V6l5-2Z"/><path d="M9 4v14M15 6v14"/></svg>"##,
        "guard" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V5l-8-3Z"/><path d="m9 12 2 2 4-4"/></svg>"##,
        "augur" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 17l5-5 3 3 5-6 5 5"/><path d="M16 9h4v4"/></svg>"##,
        "flows" => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="6" height="4" rx="1"/><rect x="15" y="9" width="6" height="4" rx="1"/><rect x="3" y="16" width="6" height="4" rx="1"/><path d="M9 6h3a2 2 0 0 1 2 2v1M9 18h3a2 2 0 0 0 2-2v-1"/></svg>"##,
        _ => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>"##,
    }
}

/// Resolve a tile's icon: prefer its explicit `icon` key, else derive a sensible glyph from
/// the display name. Lets the apex render distinct per-app icons without every `PORTAL_CATALOG`
/// entry carrying an `icon` field.
pub fn icon_for(name: &str, icon_key: &str) -> &'static str {
    if !icon_key.is_empty() {
        // A non-generic explicit key wins; an empty key falls through to the name map.
        return icon_svg(icon_key);
    }
    let key = match name {
        "Identity" => "identity",
        "Audit" => "audit",
        "Vault" => "vault",
        "Threat Intel" | "Intel" => "intel",
        "Canary" => "canary",
        "Authz" => "authz",
        "People" => "people",
        "Blog" => "blog",
        "Forum" => "forum",
        "Wiki" => "wiki",
        "Pastefire" | "Paste" => "paste",
        "Drive" => "drive",
        "Search" => "search",
        "Comments" => "comments",
        "Mail" => "mail",
        "Chat" => "chat",
        "Notify" => "bell",
        "Inbox" => "inbox",
        "Calendar" => "calendar",
        "Feeds" => "rss",
        "Clips" => "clip",
        "Social" => "social",
        "Status" => "status",
        "Vitals" => "vitals",
        "Sift" => "logs",
        "RCA" => "rca",
        "Relay" => "ai",
        "Grimoire" => "rag",
        "Familiar" => "assistant",
        "Git" => "git",
        "Registry" => "registry",
        "Events" => "events",
        "Jobs" => "jobs",
        "Backup" => "backup",
        "Lodestar" | "DNS" => "dns",
        "Ripple" => "cache",
        "Eddy" => "edge",
        "Filament" => "traces",
        "Anvil" => "ci",
        "Atlas" => "atlas",
        "Warden" => "guard",
        "Augur" => "augur",
        "Cascade" => "flows",
        _ => "",
    };
    icon_svg(key)
}

/// Time-of-day greeting from a 0..=23 hour. Kept pure so the handler computes the hour and
/// the wording stays unit-testable.
pub fn greeting(hour: u32) -> &'static str {
    match hour {
        5..=11 => "Good morning",
        12..=16 => "Good afternoon",
        _ => "Good evening",
    }
}

/// Friendly display name from a signed-in email: the local-part, first letter capitalized
/// (`alice@holdfast.local` -> `Alice`). Falls back to the whole string when there's no `@`,
/// and to `Operator` when blank.
pub fn name_from_email(email: &str) -> String {
    let local = email.split('@').next().unwrap_or(email).trim();
    if local.is_empty() {
        return "Operator".to_string();
    }
    let mut chars = local.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => "Operator".to_string(),
    }
}

/// Compact relative time ("just now", "5m ago", "3h ago", "2d ago", "4w ago") from two epoch
/// SECOND timestamps. A negative delta (clock skew) reads "just now".
pub fn rel_time(then_secs: i64, now_secs: i64) -> String {
    let d = now_secs - then_secs;
    if d < 60 {
        "just now".to_string()
    } else if d < 3_600 {
        format!("{}m ago", d / 60)
    } else if d < 86_400 {
        format!("{}h ago", d / 3_600)
    } else if d < 1_209_600 {
        format!("{}d ago", d / 86_400)
    } else {
        format!("{}w ago", d / 604_800)
    }
}

/// CSS modifier class for an audit event's severity dot. Unknown/blank severities read as
/// informational so a sparsely-tagged event still renders cleanly.
pub fn severity_dot_class(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" | "crit" | "alert" | "emergency" | "fatal" => "sev-crit",
        "error" | "err" => "sev-err",
        "warn" | "warning" => "sev-warn",
        _ => "sev-info",
    }
}

/// Format an optional percentage gauge as a clean big-number ("43%"), or the "—" placeholder
/// when the backend gave us nothing.
pub fn fmt_pct(value: Option<f64>) -> String {
    match value {
        Some(v) => format!("{:.0}%", v.clamp(0.0, 100.0)),
        None => "—".to_string(),
    }
}

/// Clamp a percentage to a 0..=100 bar width (defaults to 0 when absent).
pub fn pct_width(value: Option<f64>) -> f64 {
    value.unwrap_or(0.0).clamp(0.0, 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_by_hour() {
        assert_eq!(greeting(8), "Good morning");
        assert_eq!(greeting(14), "Good afternoon");
        assert_eq!(greeting(19), "Good evening");
        assert_eq!(greeting(2), "Good evening");
    }

    #[test]
    fn name_from_email_uses_capitalized_local_part() {
        assert_eq!(name_from_email("alice@holdfast.local"), "Alice");
        assert_eq!(name_from_email("operator"), "Operator");
        assert_eq!(name_from_email(""), "Operator");
        assert_eq!(name_from_email("  "), "Operator");
    }

    #[test]
    fn rel_time_buckets() {
        let now = 1_000_000_000;
        assert_eq!(rel_time(now, now), "just now");
        assert_eq!(rel_time(now - 30, now), "just now");
        assert_eq!(rel_time(now - 120, now), "2m ago");
        assert_eq!(rel_time(now - 7_200, now), "2h ago");
        assert_eq!(rel_time(now - 172_800, now), "2d ago");
        assert_eq!(rel_time(now - 1_814_400, now), "3w ago");
        // Clock skew (event in the future) never panics or underflows.
        assert_eq!(rel_time(now + 50, now), "just now");
    }

    #[test]
    fn severity_dot_classes() {
        assert_eq!(severity_dot_class("critical"), "sev-crit");
        assert_eq!(severity_dot_class("ERROR"), "sev-err");
        assert_eq!(severity_dot_class("warning"), "sev-warn");
        assert_eq!(severity_dot_class("info"), "sev-info");
        assert_eq!(severity_dot_class(""), "sev-info");
    }

    #[test]
    fn fmt_pct_and_width() {
        assert_eq!(fmt_pct(Some(42.7)), "43%");
        assert_eq!(fmt_pct(Some(150.0)), "100%");
        assert_eq!(fmt_pct(None), "—");
        assert_eq!(pct_width(Some(42.0)), 42.0);
        assert_eq!(pct_width(Some(-5.0)), 0.0);
        assert_eq!(pct_width(None), 0.0);
    }
}
