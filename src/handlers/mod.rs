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
        _ => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>"##,
    }
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
