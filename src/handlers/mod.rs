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
        _ => r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>"##,
    }
}
