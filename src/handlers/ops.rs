//! The federated read-only OPERATOR CONSOLE: `GET /ops`.
//!
//! ADMIN-GATED (see [`crate::auth::require_admin`] over `X-Auth-Groups` ∩ {admins, infra-admins}):
//! an ordinary signed-in user gets a 403 and the public dashboard at `/` is untouched. The gateway
//! injects AND HMAC-signs the groups on the apex route, so the membership is trustworthy.
//!
//! It is a pure read-only VIEW over the same resilient backend snapshot the dashboard uses
//! ([`crate::snapshot`]), plus a larger slice of the Watchtower audit stream:
//! 1. a cross-service AUDIT viewer (Watchtower `/api/events` newest-first + `/api/verify`), with
//!    a client-side filter (source / actor / action / severity) and "load more";
//! 2. a per-service HEALTH table from Beacon `/api/status` components (name / status / uptime);
//! 3. host metrics from Vitals.
//!
//! No writes, no store, no CSRF: every figure is best-effort and an unreachable backend degrades
//! its own panel to "—"/empty — the console never errors.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};

use crate::auth;
use crate::beacon::{Component, Statuses};
use crate::handlers::{
    esc, fmt_pct, name_from_email, rel_time, severity_dot_class, status_label, status_pill,
    APP_CSS, SHIELD_SVG,
};
use crate::snapshot::Snapshot;
use crate::vitals::Metrics;
use crate::watchtower::{Event, Verify};
use crate::AppState;

use std::time::{SystemTime, UNIX_EPOCH};

const OPS_HTML: &str = include_str!("../../templates/ops.html");

/// `GET /ops` — the operator console. 403 for a non-admin; otherwise the read-only console
/// rendered from the (cached) backend snapshot + the larger audit stream.
pub async fn ops(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if auth::require_admin(&headers).is_err() {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "the operator console requires an admin group",
        )
            .into_response();
    }

    let email = auth::signed_in_email(&headers).unwrap_or_else(|| "operator".to_string());
    // Reuse the resilient, concurrent, few-second-cached snapshot for health + metrics + verify;
    // pull a larger slice of the audit stream for the viewer table.
    let snap = state.cache.get(&state.config).await;
    let audit = crate::watchtower::fetch_audit(&state.config.watchtower_url).await;
    Html(render(&email, &snap, &audit, now_secs())).into_response()
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn render(email: &str, snap: &Snapshot, audit: &[Event], now_secs: i64) -> String {
    let name = name_from_email(email);
    let initial = name.chars().next().unwrap_or('H').to_uppercase().to_string();
    OPS_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{INITIAL}}", &esc(&initial))
        .replace("{{NAME}}", &esc(&name))
        .replace("{{EMAIL}}", &esc(email))
        .replace("{{METRICS}}", &render_metrics(&snap.metrics, &snap.verify))
        .replace("{{AUDIT_SUMMARY}}", &audit_summary(&snap.verify, audit.len()))
        .replace("{{AUDIT_ROWS}}", &render_audit_rows(audit, now_secs))
        .replace("{{HEALTH_ROWS}}", &render_health_rows(&snap.statuses))
}

// --- Host metric tiles -----------------------------------------------------------------

/// Compact host-metric tiles (CPU / memory / load) + the audit-chain count, reusing the shared
/// `.metric` card styling. Unreachable Vitals/Watchtower render "—".
fn render_metrics(m: &Metrics, verify: &Verify) -> String {
    let load = m
        .load1
        .map(|v| format!("{v:.2}"))
        .unwrap_or_else(|| "—".to_string());
    let audit = if verify.reached {
        verify.count.to_string()
    } else {
        "—".to_string()
    };
    let mut out = String::new();
    out.push_str(&metric_tile("Host CPU", &fmt_pct(m.cpu_pct)));
    out.push_str(&metric_tile("Host memory", &fmt_pct(m.mem_pct)));
    out.push_str(&metric_tile("Load · 1m", &load));
    out.push_str(&metric_tile("Audit events", &audit));
    out
}

fn metric_tile(label: &str, value: &str) -> String {
    format!(
        r#"<div class="metric"><div class="metric__top"><span class="metric__label">{label}</span></div><div class="metric__value">{value}</div></div>"#,
        label = esc(label),
        value = esc(value),
    )
}

// --- Audit viewer ----------------------------------------------------------------------

/// The audit header chip: chain length, integrity, and how many events were loaded.
fn audit_summary(verify: &Verify, loaded: usize) -> String {
    if !verify.reached {
        return r#"<span class="ops-chip"><span class="dot"></span>Watchtower unreachable</span>"#
            .to_string();
    }
    let (cls, word) = if verify.ok {
        ("is-ok", "chain verified")
    } else {
        ("is-bad", "integrity broken")
    };
    let head = if verify.head_hash.is_empty() {
        String::new()
    } else {
        let short: String = verify.head_hash.chars().take(12).collect();
        format!(
            r#" <span class="ops-chip__hash" title="{full}">head {short}</span>"#,
            full = esc(&verify.head_hash),
            short = esc(&short),
        )
    };
    format!(
        r#"<span class="ops-chip {cls}"><span class="dot"></span>{count} sealed · {word} · showing {loaded}</span>{head}"#,
        cls = cls,
        count = verify.count,
        word = word,
        loaded = loaded,
        head = head,
    )
}

/// One table row per audit event. Each row carries a lowercased `data-f` (source · actor ·
/// action · target · severity) for the free-text filter and a `data-sev` for the severity
/// select. Every field is escaped.
fn render_audit_rows(events: &[Event], now_secs: i64) -> String {
    if events.is_empty() {
        return r#"<tr class="ops-empty-row"><td colspan="6" class="ops-empty">No audit events to show.</td></tr>"#
            .to_string();
    }
    let mut out = String::new();
    for ev in events {
        let source = non_empty(&ev.source, "—");
        let actor = non_empty(&ev.actor, "system");
        let action = non_empty(&ev.action, "event");
        let target = non_empty(&ev.target, "—");
        let severity = non_empty(&ev.severity, "info");
        let when = rel_time(ev.ts / 1_000, now_secs);
        let filter = format!(
            "{} {} {} {} {}",
            source, actor, action, target, severity
        )
        .to_lowercase();
        out.push_str(&format!(
            r#"<tr class="au-row" data-f="{f}" data-sev="{sev_key}">
  <td class="au-when">{when}</td>
  <td><span class="au-sev {sevdot}">{sev}</span></td>
  <td class="au-src">{source}</td>
  <td class="au-actor">{actor}</td>
  <td class="au-action">{action}</td>
  <td class="au-target">{target}</td>
</tr>"#,
            f = esc(&filter),
            sev_key = esc(&severity.to_lowercase()),
            when = esc(&when),
            sevdot = severity_dot_class(&severity),
            sev = esc(&severity),
            source = esc(&source),
            actor = esc(&actor),
            action = esc(&action),
            target = esc(&target),
        ));
    }
    out
}

fn non_empty(s: &str, fallback: &str) -> String {
    let t = s.trim();
    if t.is_empty() {
        fallback.to_string()
    } else {
        t.to_string()
    }
}

// --- Per-service health table ----------------------------------------------------------

/// One row per Beacon component (name / live status pill / 24h uptime). An unreachable/empty
/// Beacon renders a single placeholder row.
fn render_health_rows(statuses: &Statuses) -> String {
    if !statuses.reached || statuses.components.is_empty() {
        return r#"<tr><td colspan="3" class="ops-empty">Beacon has not reported component health yet.</td></tr>"#
            .to_string();
    }
    let mut out = String::new();
    for c in &statuses.components {
        out.push_str(&health_row(c));
    }
    out
}

fn health_row(c: &Component) -> String {
    let uptime = match c.uptime_24h {
        Some(v) => format!("{:.2}%", v.clamp(0.0, 100.0)),
        None => "—".to_string(),
    };
    format!(
        r#"<tr>
  <td class="au-src" title="{title}">{name}</td>
  <td>{pill}</td>
  <td class="au-when">{uptime}</td>
</tr>"#,
        title = esc(status_label(&c.status)),
        name = esc(&c.name),
        pill = status_pill(&c.status),
        uptime = esc(&uptime),
    )
}
