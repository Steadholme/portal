//! The apex command center: `GET /` renders the HOLDFAST operations dashboard.
//!
//! A sticky app-bar (shield + wordmark, signed-in email, logout), a brand-gradient hero with
//! a time-of-day greeting, a row of LIVE METRIC CARDS (systems online, host CPU/memory, audit
//! events, load), a SERVICES grid (one live-status card per catalog entry), and a RECENT
//! ACTIVITY feed of the latest audit events. The signed-in email comes from the
//! gateway-injected `X-Auth-Email` (Portal does no login of its own).
//!
//! Every live number is best-effort: the data comes from a single cached, concurrent fetch of
//! Beacon / Vitals / Watchtower ([`crate::snapshot`]). Any unreachable backend degrades its
//! own card/pill/feed to "—"/"unknown"/empty — the page NEVER errors or hangs.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Html;

use crate::auth;
use crate::catalog::CatalogEntry;
use crate::handlers::{
    coming_soon_pill, esc, fmt_pct, greeting, icon_svg, name_from_email, pct_width, rel_time,
    severity_dot_class, status_pill, APP_CSS, SHIELD_SVG,
};
use crate::snapshot::Snapshot;
use crate::watchtower::{Event, Verify};
use crate::AppState;

const DASHBOARD_HTML: &str = include_str!("../../templates/dashboard.html");

/// `GET /` — the command center. Renders for any request the gateway forwards; the signed-in
/// email comes from the injected `X-Auth-Email`, and every live figure from the (cached)
/// concurrent backend snapshot.
pub async fn dashboard(State(state): State<AppState>, headers: HeaderMap) -> Html<String> {
    let email = auth::signed_in_email(&headers).unwrap_or_else(|| "operator".to_string());
    let snap = state.cache.get(&state.config).await;
    let (now_secs, hour) = clock();
    Html(render(&state.config.catalog, &email, &snap, now_secs, hour))
}

/// Current epoch seconds + the local-ish hour-of-day (UTC) for the greeting.
fn clock() -> (i64, u32) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let hour = ((secs.rem_euclid(86_400)) / 3_600) as u32;
    (secs, hour)
}

fn render(
    catalog: &[CatalogEntry],
    email: &str,
    snap: &Snapshot,
    now_secs: i64,
    hour: u32,
) -> String {
    let name = name_from_email(email);
    let initial = name.chars().next().unwrap_or('H').to_uppercase().to_string();
    DASHBOARD_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{INITIAL}}", &esc(&initial))
        .replace("{{EMAIL}}", &esc(email))
        .replace("{{GREETING}}", &format!("{}, {}", greeting(hour), esc(&name)))
        .replace("{{HERO_SUB}}", &hero_sub(snap))
        .replace("{{METRICS}}", &render_metrics(snap))
        .replace("{{TILES}}", &render_tiles(catalog, snap))
        .replace("{{ACTIVITY}}", &render_activity(&snap.events, now_secs))
}

/// One-line live summary under the greeting.
fn hero_sub(snap: &Snapshot) -> String {
    let mut parts: Vec<String> = Vec::new();
    if snap.statuses.reached && snap.statuses.total > 0 {
        parts.push(format!(
            "{} of {} systems operational",
            snap.statuses.up, snap.statuses.total
        ));
    }
    if snap.verify.reached {
        parts.push(format!("{} audit events sealed", snap.verify.count));
    }
    if parts.is_empty() {
        "Live telemetry is catching up — backends will report shortly.".to_string()
    } else {
        esc(&parts.join("  ·  "))
    }
}

// --- Metric cards ----------------------------------------------------------------------

/// Render the row of live metric cards.
fn render_metrics(snap: &Snapshot) -> String {
    let s = &snap.statuses;
    let systems_value = if s.reached && s.total > 0 {
        format!("{}<span class=\"metric__unit\">/{}</span>", s.up, s.total)
    } else {
        "—".to_string()
    };
    let systems_foot = if s.reached && s.total > 0 {
        let cls = if s.up == s.total { "tag tag-ok" } else { "tag tag-warn" };
        let word = if s.up == s.total { "All operational" } else { "Degraded" };
        format!(r#"<span class="{cls}">{word}</span>"#)
    } else {
        r#"<span class="metric__muted">awaiting Beacon</span>"#.to_string()
    };

    let mut out = String::new();
    out.push_str(&metric_card(
        ICON_SYSTEMS,
        "Systems online",
        &systems_value,
        &systems_foot,
        None,
    ));
    out.push_str(&metric_card(
        ICON_CPU,
        "Host CPU",
        &esc(&fmt_pct(snap.metrics.cpu_pct)),
        &gauge_foot(snap.metrics.cpu_pct),
        snap.metrics.cpu_pct.map(pct_width_opt),
    ));
    out.push_str(&metric_card(
        ICON_MEM,
        "Host memory",
        &esc(&fmt_pct(snap.metrics.mem_pct)),
        &gauge_foot(snap.metrics.mem_pct),
        snap.metrics.mem_pct.map(pct_width_opt),
    ));
    out.push_str(&metric_card(
        ICON_AUDIT,
        "Audit events",
        &audit_value(&snap.verify),
        &audit_foot(&snap.verify),
        None,
    ));
    out.push_str(&metric_card(
        ICON_LOAD,
        "Load · 1m",
        &load_value(snap.metrics.load1),
        r#"<span class="metric__muted">system load average</span>"#,
        None,
    ));
    out
}

/// A single metric card. `bar` is an optional 0..=100 fill (CPU / memory gauges only).
fn metric_card(icon: &str, label: &str, value: &str, foot: &str, bar: Option<f64>) -> String {
    let bar_html = match bar {
        Some(w) => format!(
            r#"<div class="metric__bar"><span style="width:{w:.0}%"></span></div>"#
        ),
        None => String::new(),
    };
    format!(
        r#"<div class="metric">
  <div class="metric__top">
    <span class="metric__label">{label}</span>
    <span class="metric__icon" aria-hidden="true">{icon}</span>
  </div>
  <div class="metric__value">{value}</div>
  {bar}
  <div class="metric__foot">{foot}</div>
</div>"#,
        label = esc(label),
        icon = icon,
        value = value,
        bar = bar_html,
        foot = foot,
    )
}

fn gauge_foot(value: Option<f64>) -> String {
    match value {
        Some(v) if v >= 90.0 => r#"<span class="tag tag-down">Critical</span>"#.to_string(),
        Some(v) if v >= 75.0 => r#"<span class="tag tag-warn">Elevated</span>"#.to_string(),
        Some(_) => r#"<span class="tag tag-ok">Nominal</span>"#.to_string(),
        None => r#"<span class="metric__muted">awaiting Vitals</span>"#.to_string(),
    }
}

fn load_value(load1: Option<f64>) -> String {
    match load1 {
        Some(v) => format!("{v:.2}"),
        None => "—".to_string(),
    }
}

fn audit_value(verify: &Verify) -> String {
    if verify.reached {
        verify.count.to_string()
    } else {
        "—".to_string()
    }
}

fn audit_foot(verify: &Verify) -> String {
    if !verify.reached {
        return r#"<span class="metric__muted">awaiting Watchtower</span>"#.to_string();
    }
    if verify.ok {
        r#"<span class="tag tag-ok">✓ Chain verified</span>"#.to_string()
    } else {
        r#"<span class="tag tag-down">⚠ Integrity broken</span>"#.to_string()
    }
}

/// `pct_width` already clamps; this thin wrapper keeps the `.map` closures readable.
fn pct_width_opt(v: f64) -> f64 {
    pct_width(Some(v))
}

// --- Service tiles ---------------------------------------------------------------------

/// Render the responsive grid of service cards with live status pills.
fn render_tiles(catalog: &[CatalogEntry], snap: &Snapshot) -> String {
    if catalog.is_empty() {
        return r#"<div class="empty">No services are configured.</div>"#.to_string();
    }
    let mut tiles = String::new();
    for entry in catalog {
        // Coming-soon tiles show a tag instead of a live pill; live tiles map their Beacon
        // component name to a status (defaulting to "unknown" when Beacon doesn't report it).
        let pill = if entry.coming_soon {
            coming_soon_pill()
        } else {
            status_pill(snap.statuses.status_of(&entry.component))
        };
        tiles.push_str(&format!(
            r#"<a class="tile" href="{url}">
  <div class="tile__top">
    <span class="tile__icon" aria-hidden="true">{icon}</span>
    {pill}
  </div>
  <div class="tile__name">{name}</div>
  <div class="tile__desc">{desc}</div>
  <span class="tile__go" aria-hidden="true">Open &rarr;</span>
</a>"#,
            url = esc(&entry.url),
            icon = icon_svg(&entry.icon),
            pill = pill,
            name = esc(&entry.name),
            desc = esc(&entry.description),
        ));
    }
    tiles
}

// --- Recent activity feed --------------------------------------------------------------

/// Render the recent-activity feed from the most recent audit events. Empty / unreachable
/// Watchtower shows a calm placeholder rather than an error.
fn render_activity(events: &[Event], now_secs: i64) -> String {
    if events.is_empty() {
        return r#"<div class="feed__empty">No recent activity to show.</div>"#.to_string();
    }
    let mut out = String::new();
    for ev in events {
        let action = if ev.action.trim().is_empty() {
            "event".to_string()
        } else {
            ev.action.clone()
        };
        let actor = if ev.actor.trim().is_empty() {
            "system".to_string()
        } else {
            ev.actor.clone()
        };
        // Watchtower stamps `ts` in milliseconds; relative time works in seconds.
        let when = rel_time(ev.ts / 1_000, now_secs);
        let target = if ev.target.trim().is_empty() {
            String::new()
        } else {
            format!("{} · ", esc(&ev.target))
        };
        out.push_str(&format!(
            r#"<div class="feed__item">
  <span class="feed__dot {sev}" aria-hidden="true"></span>
  <div class="feed__body">
    <div class="feed__line"><span class="feed__action">{action}</span> <span class="feed__actor">{actor}</span></div>
    <div class="feed__meta">{target}{when}</div>
  </div>
</div>"#,
            sev = severity_dot_class(&ev.severity),
            action = esc(&action),
            actor = esc(&actor),
            target = target,
            when = esc(&when),
        ));
    }
    out
}

// --- Inline metric-card glyphs ---------------------------------------------------------

const ICON_SYSTEMS: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/><path d="m8 10 2.5 2.5L16 7"/></svg>"##;
const ICON_CPU: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/></svg>"##;
const ICON_MEM: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="6" width="18" height="12" rx="2"/><path d="M7 10v4M12 10v4M17 10v4"/></svg>"##;
const ICON_AUDIT: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V5l-8-3Z"/><path d="m9 12 2 2 4-4"/></svg>"##;
const ICON_LOAD: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 13a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"/><path d="M12 4V2M4 12H2M12 20v2M20 12h2M6 6 4.5 4.5M18 6l1.5-1.5"/><path d="m12 10 4-2"/></svg>"##;
