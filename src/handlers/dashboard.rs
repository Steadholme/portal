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
    esc, fmt_pct, greeting, icon_for, name_from_email, pct_width, rel_time, severity_dot_class,
    status_label, status_pill_class, APP_CSS, SHIELD_SVG,
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
        .replace("{{NAME}}", &esc(&name))
        .replace("{{EMAIL}}", &esc(email))
        .replace("{{HEALTH_CHIP}}", &health_chip(snap))
        .replace("{{GREETING}}", &format!("{}, {}", greeting(hour), esc(&name)))
        .replace("{{HERO_SUB}}", &hero_sub(snap))
        .replace("{{METRICS}}", &render_metrics(snap))
        .replace("{{SECTIONS}}", &render_sections(catalog, snap))
        .replace("{{ACTIVITY}}", &render_activity(&snap.events, now_secs))
}

/// The app-bar health chip: "N/M operational" tinted by whether everything is up. Degrades to
/// a neutral "status syncing" label until Beacon first reports.
fn health_chip(snap: &Snapshot) -> String {
    let s = &snap.statuses;
    if s.reached && s.total > 0 {
        let cls = if s.up == s.total { "is-ok" } else { "is-warn" };
        format!(
            r#"<span class="healthchip {cls}"><span class="dot"></span>{up}/{total} operational</span>"#,
            cls = cls,
            up = s.up,
            total = s.total,
        )
    } else {
        r#"<span class="healthchip"><span class="dot"></span>status syncing</span>"#.to_string()
    }
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

// --- App chiclets, grouped into Okta-style sections ------------------------------------

/// The fixed section order + display label. A catalog entry is placed by [`category_key`];
/// the section is rendered only when at least one app falls in it.
const SECTION_ORDER: &[(&str, &str)] = &[
    ("ident", "Identity & Security"),
    ("content", "Content & Knowledge"),
    ("comms", "Communication"),
    ("obs", "Observability"),
    ("ai", "AI & Assistants"),
    ("dev", "Developer & Platform"),
    ("more", "More"),
];

/// Map a tile's display name to its section key. Unknown names land in "more" so a newly
/// added service still renders cleanly without a code change.
fn category_key(name: &str) -> &'static str {
    match name {
        "Identity" | "Audit" | "Vault" | "Threat Intel" | "Intel" | "Canary" | "Authz"
        | "People" => "ident",
        "Blog" | "Forum" | "Wiki" | "Pastefire" | "Paste" | "Search" | "Drive" | "Comments" => {
            "content"
        }
        "Mail" | "Chat" | "Notify" | "Inbox" | "Calendar" | "Feeds" | "Clips" | "Social" => {
            "comms"
        }
        "Status" | "Vitals" | "Sift" | "RCA" => "obs",
        "Relay" | "Grimoire" | "Familiar" => "ai",
        "Git" | "Registry" | "Events" | "Jobs" | "Backup" | "Lodestar" | "DNS" => "dev",
        _ => "more",
    }
}

/// Render the app chiclets grouped into the fixed sections (Okta end-user dashboard layout).
fn render_sections(catalog: &[CatalogEntry], snap: &Snapshot) -> String {
    if catalog.is_empty() {
        return r#"<div class="empty">No apps are configured.</div>"#.to_string();
    }
    let mut out = String::new();
    for (key, label) in SECTION_ORDER {
        let apps: Vec<&CatalogEntry> = catalog
            .iter()
            .filter(|e| category_key(&e.name) == *key)
            .collect();
        if apps.is_empty() {
            continue;
        }
        out.push_str(&format!(
            r#"<section class="appsec" data-section><h2 class="appsec__title">{label}</h2><div class="appgrid">"#,
            label = esc(label),
        ));
        for entry in apps {
            out.push_str(&render_app(entry, key, snap));
        }
        out.push_str("</div></section>");
    }
    out
}

/// One app chiclet: a category-tinted icon tile, the app name + description, and a live status
/// dot (top-right). Coming-soon services show a "Soon" badge and an accent dot.
fn render_app(entry: &CatalogEntry, cat_key: &str, snap: &Snapshot) -> String {
    let (dot_class, title, soon_badge) = if entry.coming_soon {
        (
            "pill-soon".to_string(),
            "Coming soon".to_string(),
            r#"<span class="app__soon">Soon</span>"#.to_string(),
        )
    } else {
        let status = snap.statuses.status_of(&entry.component);
        (
            status_pill_class(status).to_string(),
            status_label(status).to_string(),
            String::new(),
        )
    };
    // Lowercased name+description backs the client-side app search filter.
    let data_name = esc(&format!("{} {}", entry.name, entry.description).to_lowercase());
    format!(
        r#"<a class="app app--{cat}" href="{url}" data-name="{dn}">
  {soon}
  <span class="app__status {dot}" title="{title}" aria-label="{title}"></span>
  <span class="app__icon" aria-hidden="true">{icon}</span>
  <span class="app__name">{name}</span>
  <span class="app__desc">{desc}</span>
</a>"#,
        cat = cat_key,
        url = esc(&entry.url),
        dn = data_name,
        soon = soon_badge,
        dot = dot_class,
        title = esc(&title),
        icon = icon_for(&entry.name, &entry.icon),
        name = esc(&entry.name),
        desc = esc(&entry.description),
    )
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
