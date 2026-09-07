//! The admin-gated operator console: `GET /ops` — the sealed audit stream.
//!
//! ADMIN-GATED (see [`crate::auth::require_admin`] over `X-Auth-Groups` ∩ {admins, infra-admins}):
//! an ordinary signed-in user gets a 403 and the public launcher at `/` is untouched. The gateway
//! injects AND HMAC-signs the groups on the apex route, so the membership is trustworthy.
//!
//! It is a pure read-only VIEW over the same resilient backend snapshot the launcher uses
//! ([`crate::snapshot`]), plus a larger slice of the Watchtower audit stream:
//! 1. a summary strip (chain length + verdict, fleet up/total, host gauges, matching events);
//! 2. the cross-service AUDIT stream (Watchtower `/api/events` newest-first + `/api/verify`)
//!    grouped by day, with SERVER-SIDE filters as GET query params (source / actor / action
//!    substrings + a time range with 1h/24h/7d presets and custom epoch bounds), prev/next
//!    pagination preserving the filters, and a per-event `<details>` record that the
//!    client-side inspector mirrors;
//! 3. host metrics from Vitals under the Host view.
//!
//! Service health is Beacon's surface, not Portal's — only the fleet up/total appears here.
//!
//! FILTER PUSH-DOWN: Watchtower's `/api/events` only supports `actor`/`action` as EXACT matches,
//! `since`, and `q` — no `source` param and no upper time bound. So the handler pushes down only
//! the lower time bound (`?since=`, epoch ms) and applies the substring/source/`to` filters over
//! the fetched window (capped at [`crate::watchtower::AUDIT_MAX`]) itself.
//!
//! No writes, no store, no CSRF: every figure is best-effort and an unreachable backend degrades
//! its own panel to "—"/empty — the console never errors. The query string is parsed leniently
//! for the same reason (a malformed param falls back to its default rather than a 400).

use axum::extract::{RawQuery, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};

use crate::auth;
use crate::beacon::Statuses;
use crate::handlers::{
    esc, fmt_count, fmt_pct, name_from_email, pct_width, rel_time, severity_dot_class,
    status_label, SHIELD_SVG,
};
use crate::snapshot::Snapshot;
use crate::vitals::Metrics;
use crate::watchtower::{Event, Verify};
use crate::AppState;

use std::time::{SystemTime, UNIX_EPOCH};

const OPS_HTML: &str = include_str!("../../templates/ops.html");

/// How many audit events one page of the stream shows.
pub const PAGE_SIZE: usize = 25;

/// `GET /ops` — the operator console. 403 for a non-admin; otherwise the read-only console
/// rendered from the (cached) backend snapshot + the filtered, paginated audit stream.
pub async fn ops(
    State(state): State<AppState>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Response {
    if auth::require_admin(&headers).is_err() {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "the operator console requires an admin group",
        )
            .into_response();
    }

    let email = auth::signed_in_email(&headers).unwrap_or_else(|| "operator".to_string());
    let query = parse_query(raw.as_deref().unwrap_or(""));
    let now = now_secs();
    let (from_ms, to_ms) = query.window_ms(now);

    // Reuse the resilient, concurrent, few-second-cached snapshot for fleet + metrics + verify;
    // pull a larger slice of the audit stream for the viewer. The lower time bound is pushed
    // down as Watchtower's native `?since=`; the remaining filters are applied here (see the
    // module docs — the API has no substring/source/`until` params). The local time checks are
    // repeated over the fetched window, so a Watchtower that ignored `since` stays correct.
    let snap = state.cache.get(&state.config).await;
    let audit = crate::watchtower::fetch_audit(&state.config.watchtower_url, from_ms).await;
    let filtered: Vec<&Event> = audit
        .iter()
        .filter(|e| query.matches(e, from_ms, to_ms))
        .collect();
    Html(render(&email, &snap, &filtered, &query, now)).into_response()
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// --- Audit query parsing ---------------------------------------------------------------

/// The audit stream's GET query params, parsed LENIENTLY (a malformed value falls back to
/// its default — the console never 400s). `source`/`actor`/`action` are case-insensitive
/// substring filters; `range` is one of `1h`/`24h`/`7d`/`custom` (empty = all time);
/// `from`/`to` are the custom bounds in epoch SECONDS; `page` is 1-based.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AuditQuery {
    pub source: String,
    pub actor: String,
    pub action: String,
    pub range: String,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub page: usize,
}

/// Parse the raw `/ops` query string. Unknown keys are ignored; blank values are absent;
/// non-numeric `from`/`to`/`page` and unknown `range` presets fall back to their defaults.
pub fn parse_query(raw: &str) -> AuditQuery {
    let mut q = AuditQuery {
        page: 1,
        ..AuditQuery::default()
    };
    for pair in raw.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = url_decode(v);
        let v = v.trim();
        if v.is_empty() {
            continue;
        }
        match url_decode(k).as_str() {
            "source" => q.source = v.to_string(),
            "actor" => q.actor = v.to_string(),
            "action" => q.action = v.to_string(),
            "range" => {
                if matches!(v, "1h" | "24h" | "7d" | "custom") {
                    q.range = v.to_string();
                }
            }
            "from" => q.from = v.parse().ok().filter(|n: &i64| *n >= 0),
            "to" => q.to = v.parse().ok().filter(|n: &i64| *n >= 0),
            "page" => q.page = v.parse().unwrap_or(1).max(1),
            _ => {}
        }
    }
    q
}

impl AuditQuery {
    /// The effective time window as epoch-MILLISECOND bounds `(from, to)`. Presets are
    /// relative to `now_secs`; `custom` uses the epoch-second inputs (either may be absent);
    /// no/unknown range means unbounded.
    pub fn window_ms(&self, now_secs: i64) -> (Option<i64>, Option<i64>) {
        let preset = |secs: i64| (Some((now_secs - secs) * 1_000), None);
        match self.range.as_str() {
            "1h" => preset(3_600),
            "24h" => preset(86_400),
            "7d" => preset(604_800),
            "custom" => (
                self.from.map(|s| s.saturating_mul(1_000)),
                self.to.map(|s| s.saturating_mul(1_000)),
            ),
            _ => (None, None),
        }
    }

    /// Does one event pass every filter? Substrings are case-insensitive; the time bounds
    /// are epoch ms (see [`AuditQuery::window_ms`]).
    pub fn matches(&self, ev: &Event, from_ms: Option<i64>, to_ms: Option<i64>) -> bool {
        contains_ci(&ev.source, &self.source)
            && contains_ci(&ev.actor, &self.actor)
            && contains_ci(&ev.action, &self.action)
            && from_ms.is_none_or(|f| ev.ts >= f)
            && to_ms.is_none_or(|t| ev.ts <= t)
    }

    /// Rebuild the query string for a pager link targeting `page`, preserving every active
    /// filter. Values are percent-encoded; the caller HTML-escapes the whole URL for the
    /// `href` attribute (turning the `&` separators into `&amp;`).
    fn query_string(&self, page: usize) -> String {
        let mut parts: Vec<String> = Vec::new();
        for (key, value) in [
            ("source", &self.source),
            ("actor", &self.actor),
            ("action", &self.action),
            ("range", &self.range),
        ] {
            if !value.is_empty() {
                parts.push(format!("{key}={}", url_encode(value)));
            }
        }
        if let Some(f) = self.from {
            parts.push(format!("from={f}"));
        }
        if let Some(t) = self.to {
            parts.push(format!("to={t}"));
        }
        parts.push(format!("page={page}"));
        parts.join("&")
    }

    /// The query string with one filter cleared (page reset to 1) — the chip "Clear" links.
    fn query_string_without(&self, key: &str) -> String {
        let mut cleared = self.clone();
        match key {
            "source" => cleared.source.clear(),
            "actor" => cleared.actor.clear(),
            "action" => cleared.action.clear(),
            "range" => {
                cleared.range.clear();
                cleared.from = None;
                cleared.to = None;
            }
            _ => {}
        }
        cleared.query_string(1)
    }

    fn range_label(&self) -> Option<&'static str> {
        match self.range.as_str() {
            "1h" => Some("1h"),
            "24h" => Some("24h"),
            "7d" => Some("7d"),
            "custom" => Some("custom"),
            _ => None,
        }
    }
}

/// Case-insensitive substring match; an empty needle matches everything (filter unset).
fn contains_ci(hay: &str, needle: &str) -> bool {
    needle.is_empty() || hay.to_lowercase().contains(&needle.to_lowercase())
}

/// Decode one `application/x-www-form-urlencoded` value: `+` -> space, `%XX` -> byte.
/// Malformed escapes pass through literally (lenient, never errors).
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encode a query VALUE (everything but RFC 3986 unreserved characters).
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// --- Page render -----------------------------------------------------------------------

fn render(
    email: &str,
    snap: &Snapshot,
    filtered: &[&Event],
    query: &AuditQuery,
    now_secs: i64,
) -> String {
    let name = name_from_email(email);
    let initial = name
        .chars()
        .next()
        .unwrap_or('H')
        .to_uppercase()
        .to_string();

    // Paginate the FILTERED result; an out-of-range page clamps to the last one.
    let pages = filtered.len().div_ceil(PAGE_SIZE).max(1);
    let page = query.page.clamp(1, pages);
    let start = (page - 1) * PAGE_SIZE;
    let slice = &filtered[start.min(filtered.len())..(start + PAGE_SIZE).min(filtered.len())];

    OPS_HTML
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{INITIAL}}", &esc(&initial))
        .replace("{{NAME}}", &esc(&name))
        .replace("{{EMAIL}}", &esc(email))
        .replace("{{CHAIN_STATE}}", chain_state(&snap.verify))
        .replace(
            "{{STRIP}}",
            &render_strip(snap, &snap.operator_statuses, filtered.len()),
        )
        .replace("{{METRICS}}", &render_metrics(&snap.metrics, &snap.verify))
        .replace(
            "{{AUDIT_SUMMARY}}",
            &audit_summary(&snap.verify, filtered.len()),
        )
        .replace("{{AUDIT_FILTERS}}", &render_audit_filters(query))
        .replace("{{AUDIT_ROWS}}", &render_audit_rows(slice, now_secs))
        .replace(
            "{{AUDIT_PAGER}}",
            &render_audit_pager(query, page, pages, filtered.len()),
        )
}

/// Chain verdict token: `ok`, `bad` (reached but broken) or `unknown` (Watchtower down).
fn chain_state(verify: &Verify) -> &'static str {
    if !verify.reached {
        "unknown"
    } else if verify.ok {
        "ok"
    } else {
        "bad"
    }
}

// --- Summary strip ---------------------------------------------------------------------

/// The instrument strip: chain, fleet, CPU, memory, load, matching events. Every cell is a
/// label + value; an unreachable backend renders "—".
fn render_strip(snap: &Snapshot, statuses: &Statuses, matching: usize) -> String {
    let verify = &snap.verify;
    let (chain_value, chain_unit, chain_tone) = if !verify.reached {
        ("—".to_string(), "", "unknown")
    } else if verify.ok {
        (fmt_count(verify.count), "sealed", "operational")
    } else {
        (fmt_count(verify.count), "broken", "down")
    };
    let (fleet_value, fleet_unit, fleet_tone) = if statuses.reached && statuses.total > 0 {
        let troubled: Vec<_> = statuses
            .components
            .iter()
            .filter(|c| c.status != "operational")
            .collect();
        let unit = match troubled.first() {
            None => "up".to_string(),
            Some(first) => {
                let mut unit = format!(
                    "{} {}",
                    esc(&first.name),
                    status_label(&first.status).to_lowercase()
                );
                if troubled.len() > 1 {
                    unit.push_str(&format!(" +{}", troubled.len() - 1));
                }
                unit
            }
        };
        let tone = if troubled.is_empty() {
            "operational"
        } else if troubled.iter().any(|c| c.status == "down") {
            "down"
        } else {
            "degraded"
        };
        (format!("{}/{}", statuses.up, statuses.total), unit, tone)
    } else {
        ("—".to_string(), String::new(), "unknown")
    };
    let load = snap
        .metrics
        .load1
        .map(|v| format!("{v:.2}"))
        .unwrap_or_else(|| "—".to_string());
    [
        cell("Chain", &chain_value, chain_unit, chain_tone),
        cell("Fleet", &fleet_value, &fleet_unit, fleet_tone),
        cell(
            "CPU",
            &fmt_pct(snap.metrics.cpu_pct),
            "",
            gauge_tone(snap.metrics.cpu_pct),
        ),
        cell(
            "Memory",
            &fmt_pct(snap.metrics.mem_pct),
            "",
            gauge_tone(snap.metrics.mem_pct),
        ),
        cell("Load", &load, "", "neutral"),
        cell("Events", &fmt_count(matching), "matching", "neutral"),
    ]
    .concat()
}

fn cell(label: &str, value: &str, unit: &str, tone: &str) -> String {
    let unit_html = if unit.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="cell__unit">{unit}</span>"#)
    };
    format!(
        r#"<div class="cell" data-state="{tone}"><span class="cell__label">{label}</span><span class="cell__value">{value}{unit}</span></div>"#,
        tone = tone,
        label = esc(label),
        value = esc(value),
        unit = unit_html,
    )
}

fn gauge_tone(value: Option<f64>) -> &'static str {
    match value {
        Some(v) if v >= 90.0 => "down",
        Some(v) if v >= 75.0 => "degraded",
        Some(_) => "neutral",
        None => "unknown",
    }
}

// --- Host metric tiles -----------------------------------------------------------------

/// Host tiles (CPU / memory / load) + the audit-chain count. Unreachable Vitals/Watchtower
/// render "—".
fn render_metrics(m: &Metrics, verify: &Verify) -> String {
    let load = m
        .load1
        .map(|v| format!("{v:.2}"))
        .unwrap_or_else(|| "—".to_string());
    let audit = if verify.reached {
        fmt_count(verify.count)
    } else {
        "—".to_string()
    };
    [
        metric_tile(
            "Host CPU",
            &fmt_pct(m.cpu_pct),
            m.cpu_pct.map(|v| pct_width(Some(v))),
            gauge_tone(m.cpu_pct),
        ),
        metric_tile(
            "Host memory",
            &fmt_pct(m.mem_pct),
            m.mem_pct.map(|v| pct_width(Some(v))),
            gauge_tone(m.mem_pct),
        ),
        metric_tile("Load · 1m", &load, None, "neutral"),
        metric_tile("Audit events", &audit, None, chain_state(verify)),
    ]
    .concat()
}

fn metric_tile(label: &str, value: &str, bar: Option<f64>, tone: &str) -> String {
    let bar_html = match bar {
        Some(w) => format!(r#"<div class="metric__bar"><span style="width:{w:.0}%"></span></div>"#),
        None => String::new(),
    };
    format!(
        r#"<div class="metric" data-state="{tone}"><div class="metric__top"><span class="metric__label">{label}</span></div><div class="metric__value">{value}</div>{bar}</div>"#,
        tone = tone,
        label = esc(label),
        value = esc(value),
        bar = bar_html,
    )
}

// --- Audit stream ----------------------------------------------------------------------

/// The audit summary: chain length, integrity verdict, how many events match the filters,
/// and the head hash.
fn audit_summary(verify: &Verify, loaded: usize) -> String {
    if !verify.reached {
        return r#"<span class="ops-chip"><span class="dot"></span>Watchtower —</span>"#
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
            r#" <span class="hash" title="{full}">head {short}</span>"#,
            full = esc(&verify.head_hash),
            short = esc(&short),
        )
    };
    format!(
        r#"<span class="ops-chip {cls}"><span class="dot"></span>{count} sealed · {word} · showing {loaded}</span>{head}"#,
        cls = cls,
        count = fmt_count(verify.count),
        word = word,
        loaded = fmt_count(loaded),
        head = head,
    )
}

/// The filter controls: an action search plus Source / Actor / Range chips. Each chip is a
/// native `<details>` popover holding its input, so the GET form works without JavaScript;
/// an active chip shows its value and a Clear link. Values are echoed escaped.
fn render_audit_filters(q: &AuditQuery) -> String {
    let sel = |v: &str| if q.range == v { " selected" } else { "" };
    let from = q.from.map(|v| v.to_string()).unwrap_or_default();
    let to = q.to.map(|v| v.to_string()).unwrap_or_default();
    let range_active = q.range_label().is_some();
    let range_clear = if range_active {
        format!(
            r##"<a href="/ops?{qs}#audit">Clear</a>"##,
            qs = esc(&q.query_string_without("range"))
        )
    } else {
        String::new()
    };
    format!(
        r#"<input class="filters__search" type="search" name="action" value="{action}" placeholder="Action" autocomplete="off" aria-label="Filter by action">
{source}
{actor}
<details class="fchip{range_class}"><summary><span class="fchip__label">Range</span>{range_value}{chevron}</summary><div class="fchip__pop">
  <select class="ops-select" name="range" aria-label="Time range">
    <option value="">All time</option>
    <option value="1h"{s1}>Last hour</option>
    <option value="24h"{s24}>Last 24 hours</option>
    <option value="7d"{s7}>Last 7 days</option>
    <option value="custom"{sc}>Custom range</option>
  </select>
  <div class="fchip__row"><input class="ops-input" name="from" value="{from}" inputmode="numeric" placeholder="From · epoch s" aria-label="Custom range start (epoch seconds)"><input class="ops-input" name="to" value="{to}" inputmode="numeric" placeholder="To · epoch s" aria-label="Custom range end (epoch seconds)"></div>
  <div class="fchip__row"><button class="btn btn-secondary btn-sm" type="submit">Apply</button>{range_clear}</div>
</div></details>"#,
        action = esc(&q.action),
        source = filter_chip("Source", "source", &q.source, "Service / source", q),
        actor = filter_chip("Actor", "actor", &q.actor, "Actor", q),
        range_class = if range_active { " is-active" } else { "" },
        range_value = q
            .range_label()
            .map(|label| format!(r#"<span class="fchip__value">· {label}</span>"#))
            .unwrap_or_default(),
        chevron = ICON_CHEVRON,
        s1 = sel("1h"),
        s24 = sel("24h"),
        s7 = sel("7d"),
        sc = sel("custom"),
        from = esc(&from),
        to = esc(&to),
        range_clear = range_clear,
    )
}

fn filter_chip(label: &str, name: &str, value: &str, placeholder: &str, q: &AuditQuery) -> String {
    let active = !value.is_empty();
    let clear = if active {
        format!(
            r##"<a href="/ops?{qs}#audit">Clear</a>"##,
            qs = esc(&q.query_string_without(name))
        )
    } else {
        String::new()
    };
    format!(
        r#"<details class="fchip{cls}"><summary><span class="fchip__label">{label}</span>{shown}{chevron}</summary><div class="fchip__pop"><input class="ops-input" type="search" name="{name}" value="{value}" placeholder="{placeholder}" autocomplete="off" aria-label="Filter by {label}"><div class="fchip__row"><button class="btn btn-secondary btn-sm" type="submit">Apply</button>{clear}</div></div></details>"#,
        cls = if active { " is-active" } else { "" },
        label = esc(label),
        shown = if active {
            format!(r#"<span class="fchip__value">· {}</span>"#, esc(value))
        } else {
            String::new()
        },
        chevron = ICON_CHEVRON,
        name = name,
        value = esc(value),
        placeholder = esc(placeholder),
        clear = clear,
    )
}

/// The stream: one row per audit event on the current page, grouped under a day label
/// (Today / Yesterday / ISO date, UTC). Each row keeps a no-JS `<details>` record with the
/// FULL sealed metadata; every field is escaped. Rows carry a lowercased `data-sev` hook.
fn render_audit_rows(events: &[&Event], now_secs: i64) -> String {
    if events.is_empty() {
        return r#"<li class="ops-empty">No audit events to show.</li>"#.to_string();
    }
    let mut out = String::new();
    let mut last_day: Option<String> = None;
    for ev in events {
        let day = day_label(ev.ts / 1_000, now_secs);
        if last_day.as_deref() != Some(day.as_str()) {
            out.push_str(&format!(r#"<li class="au-day">{}</li>"#, esc(&day)));
            last_day = Some(day);
        }
        let source = non_empty(&ev.source, "—");
        let actor = non_empty(&ev.actor, "system");
        let action = non_empty(&ev.action, "event");
        let target = non_empty(&ev.target, "");
        let severity = non_empty(&ev.severity, "info");
        let when = rel_time(ev.ts / 1_000, now_secs);
        out.push_str(&format!(
            r#"<li class="au-row" data-sev="{sev_key}" data-seq="{seq}">
  <span class="au-when" data-spark-reltime data-ts="{ts}">{when}</span>
  <span class="au-rail {sevdot}" aria-hidden="true"></span>
  <span class="au-main"><span class="au-action">{action}</span><span class="au-target">{target}</span></span>
  <span class="au-src">{source}</span>
  <span class="au-actor">{actor}</span>
  {detail}
</li>"#,
            sev_key = esc(&severity.to_lowercase()),
            seq = ev.seq,
            ts = ev.ts / 1_000,
            when = esc(&when),
            sevdot = severity_dot_class(&severity),
            action = esc(&action),
            target = esc(&target),
            source = esc(&source),
            actor = esc(&actor),
            detail = render_event_detail(ev),
        ));
    }
    out
}

/// Day bucket for the stream, in UTC: "Today", "Yesterday", else the ISO date.
fn day_label(ts_secs: i64, now_secs: i64) -> String {
    let day = ts_secs.div_euclid(86_400);
    let today = now_secs.div_euclid(86_400);
    match today - day {
        0 => "Today".to_string(),
        1 => "Yesterday".to_string(),
        _ => {
            let (y, m, d) = civil_from_days(day);
            format!("{y:04}-{m:02}-{d:02}")
        }
    }
}

/// Days since 1970-01-01 -> proleptic Gregorian (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The per-event record: a plain `<details>/<summary>` (no JS) listing the full sealed
/// metadata — sequence, raw timestamp, every content field, and both chain hashes. The
/// client-side inspector reads the same `<dl>`. Everything is escaped; absent fields render "—".
fn render_event_detail(ev: &Event) -> String {
    let seq = if ev.seq > 0 {
        ev.seq.to_string()
    } else {
        "—".to_string()
    };
    let fields = [
        ("Seq", seq),
        ("Timestamp", format!("{} ms", ev.ts)),
        ("Source", non_empty(&ev.source, "—")),
        ("Actor", non_empty(&ev.actor, "system")),
        ("Action", non_empty(&ev.action, "event")),
        ("Target", non_empty(&ev.target, "—")),
        ("Severity", non_empty(&ev.severity, "info")),
        ("Detail", non_empty(&ev.detail, "—")),
        ("Prev hash", non_empty(&ev.prev_hash, "—")),
        ("Hash", non_empty(&ev.hash, "—")),
    ];
    let mut dl = String::new();
    for (label, value) in fields {
        dl.push_str(&format!(
            "<dt>{label}</dt><dd>{value}</dd>",
            label = esc(label),
            value = esc(&value),
        ));
    }
    format!(
        r#"<details class="au-detail"><summary>Detail</summary><dl class="au-detail__meta">{dl}</dl></details>"#
    )
}

/// The prev/next pager under the stream. Links rebuild the current query string (every
/// filter preserved, values percent-encoded) and are HTML-escaped for the attribute — so the
/// `&` separators render as `&amp;`.
fn render_audit_pager(q: &AuditQuery, page: usize, pages: usize, total: usize) -> String {
    if total == 0 {
        return r#"<span class="ops-pager__info">No events match the current filters.</span>"#
            .to_string();
    }
    let mut out = String::new();
    if page > 1 {
        out.push_str(&format!(
            r#"<a class="loadmore" href="/ops?{qs}#audit">&larr; Prev</a>"#,
            qs = esc(&q.query_string(page - 1)),
        ));
    }
    out.push_str(&format!(
        r#"<span class="ops-pager__info">Page {page} of {pages} · {total} events</span>"#
    ));
    if page < pages {
        out.push_str(&format!(
            r#"<a class="loadmore" href="/ops?{qs}#audit">Next &rarr;</a>"#,
            qs = esc(&q.query_string(page + 1)),
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

const ICON_CHEVRON: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>"##;

#[cfg(test)]
mod tests {
    use super::*;

    fn event(ts: i64, source: &str, actor: &str, action: &str) -> Event {
        Event {
            seq: 1,
            ts,
            source: source.to_string(),
            actor: actor.to_string(),
            action: action.to_string(),
            target: "t".to_string(),
            severity: "info".to_string(),
            detail: String::new(),
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    #[test]
    fn parse_query_defaults_when_absent() {
        let q = parse_query("");
        assert_eq!(q.page, 1);
        assert!(q.source.is_empty() && q.actor.is_empty() && q.action.is_empty());
        assert!(q.range.is_empty());
        assert_eq!(q.from, None);
        assert_eq!(q.to, None);
    }

    #[test]
    fn parse_query_reads_every_param_and_decodes() {
        let q = parse_query(
            "source=key%20stone&actor=alice%40steadholme.local&action=key.revoke&range=24h&from=100&to=200&page=3",
        );
        assert_eq!(q.source, "key stone");
        assert_eq!(q.actor, "alice@steadholme.local");
        assert_eq!(q.action, "key.revoke");
        assert_eq!(q.range, "24h");
        assert_eq!(q.from, Some(100));
        assert_eq!(q.to, Some(200));
        assert_eq!(q.page, 3);

        // `+` decodes to a space; blank values read as absent.
        let q = parse_query("actor=a+b&source=&range=");
        assert_eq!(q.actor, "a b");
        assert!(q.source.is_empty());
        assert!(q.range.is_empty());
    }

    #[test]
    fn parse_query_is_lenient_on_garbage() {
        // Non-numeric page/from/to, negative epochs, an unknown preset, and unknown keys all
        // fall back to defaults — the console never 400s.
        let q = parse_query("page=abc&from=-5&to=xyz&range=nope&bogus=1&%ZZ=2");
        assert_eq!(q.page, 1);
        assert_eq!(q.from, None);
        assert_eq!(q.to, None);
        assert!(q.range.is_empty());

        let q = parse_query("page=0");
        assert_eq!(q.page, 1, "page clamps to 1");
    }

    #[test]
    fn window_ms_presets_and_custom_bounds() {
        let now = 1_700_000_000;
        let q = parse_query("range=1h");
        assert_eq!(q.window_ms(now), (Some((now - 3_600) * 1_000), None));
        let q = parse_query("range=24h");
        assert_eq!(q.window_ms(now), (Some((now - 86_400) * 1_000), None));
        let q = parse_query("range=7d");
        assert_eq!(q.window_ms(now), (Some((now - 604_800) * 1_000), None));

        // Custom uses the epoch-second inputs (converted to ms); either side may be open.
        let q = parse_query("range=custom&from=100&to=200");
        assert_eq!(q.window_ms(now), (Some(100_000), Some(200_000)));
        let q = parse_query("range=custom&to=200");
        assert_eq!(q.window_ms(now), (None, Some(200_000)));

        // No range -> unbounded, and custom bounds without range=custom are ignored.
        let q = parse_query("from=100&to=200");
        assert_eq!(q.window_ms(now), (None, None));
    }

    #[test]
    fn matches_filters_substrings_case_insensitively() {
        let ev = event(1_000, "Keystone", "alice@steadholme.local", "key.revoke");
        let q = parse_query("source=keys&actor=ALICE&action=revoke");
        assert!(q.matches(&ev, None, None));

        assert!(!parse_query("source=relay").matches(&ev, None, None));
        assert!(!parse_query("actor=bob").matches(&ev, None, None));
        assert!(!parse_query("action=login").matches(&ev, None, None));
        assert!(
            parse_query("").matches(&ev, None, None),
            "no filters match all"
        );
    }

    #[test]
    fn matches_applies_time_bounds_in_ms() {
        let ev = event(5_000, "s", "a", "act");
        let q = parse_query("");
        assert!(
            q.matches(&ev, Some(5_000), Some(5_000)),
            "bounds are inclusive"
        );
        assert!(!q.matches(&ev, Some(5_001), None), "below the lower bound");
        assert!(!q.matches(&ev, None, Some(4_999)), "above the upper bound");
    }

    #[test]
    fn query_string_preserves_filters_and_encodes_values() {
        let q = parse_query("source=a%26b&actor=x+y&range=custom&from=1&to=2&page=9");
        assert_eq!(
            q.query_string(2),
            "source=a%26b&actor=x%20y&range=custom&from=1&to=2&page=2"
        );
        // Unset filters are omitted entirely.
        assert_eq!(parse_query("").query_string(1), "page=1");
        // Clearing one chip keeps the others and drops the custom bounds with the range.
        assert_eq!(
            q.query_string_without("source"),
            "actor=x%20y&range=custom&from=1&to=2&page=1"
        );
        assert_eq!(
            q.query_string_without("range"),
            "source=a%26b&actor=x%20y&page=1"
        );
    }

    #[test]
    fn pager_links_preserve_filters_and_escape_ampersands() {
        let q = parse_query("actor=a%26b&page=2");
        let html = render_audit_pager(&q, 2, 3, 60);
        assert!(html.contains("Page 2 of 3 · 60 events"));
        assert!(
            html.contains(r#"href="/ops?actor=a%26b&amp;page=1#audit""#),
            "prev link keeps the filter, ampersand-escaped: {html}"
        );
        assert!(
            html.contains(r#"href="/ops?actor=a%26b&amp;page=3#audit""#),
            "next link keeps the filter, ampersand-escaped: {html}"
        );

        // Boundary pages drop the dangling link; an empty result explains itself.
        let first = render_audit_pager(&q, 1, 3, 60);
        assert!(!first.contains("Prev"));
        let last = render_audit_pager(&q, 3, 3, 60);
        assert!(!last.contains("Next"));
        assert!(render_audit_pager(&q, 1, 1, 0).contains("No events match"));
    }

    #[test]
    fn filter_chips_echo_values_escaped_and_expose_clear_links() {
        let q = parse_query("source=%3Cb%3E&actor=o%27hara&range=7d");
        let html = render_audit_filters(&q);
        assert!(
            html.contains(r#"value="&lt;b&gt;""#),
            "source echoed escaped"
        );
        assert!(
            html.contains(r#"value="o&#x27;hara""#),
            "actor echoed escaped"
        );
        assert!(
            html.contains(r#"<option value="7d" selected>"#),
            "preset stays selected"
        );
        assert!(
            html.contains(r#"<details class="fchip is-active">"#),
            "active chips are marked"
        );
        assert!(
            html.contains(
                r##"href="/ops?actor=o%27hara&amp;range=7d&amp;page=1#audit">Clear</a>"##
            ),
            "clearing source keeps actor + range: {html}"
        );
        assert!(!html.contains("<b>"), "no raw user HTML in the form");
    }

    #[test]
    fn stream_groups_rows_by_utc_day() {
        let now = 1_700_000_000; // 2023-11-14T22:13:20Z
        let today = event(1_699_990_000_000, "keystone", "alice", "login");
        let yesterday = event(1_699_900_000_000, "relay", "bob", "key.revoke");
        let older = event(1_699_000_000_000, "vault", "carol", "lease.revoke");
        let html = render_audit_rows(&[&today, &yesterday, &older], now);
        assert!(html.contains(r#"<li class="au-day">Today</li>"#));
        assert!(html.contains(r#"<li class="au-day">Yesterday</li>"#));
        assert!(html.contains(r#"<li class="au-day">2023-11-03</li>"#));
        assert_eq!(html.matches(r#"class="au-row""#).count(), 3);
        assert_eq!(day_label(0, 0), "Today");
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
    }

    #[test]
    fn event_detail_renders_full_metadata_escaped() {
        let mut ev = event(1_700_000_000_000, "keystone", "alice", "login");
        ev.seq = 42;
        ev.detail = "<script>alert(1)</script>".to_string();
        ev.prev_hash = "aa11".to_string();
        ev.hash = "bb22".to_string();
        let html = render_event_detail(&ev);
        assert!(html.contains("<details"), "uses a details/summary expander");
        assert!(html.contains("<dt>Seq</dt><dd>42</dd>"));
        assert!(html.contains("1700000000000 ms"), "raw timestamp shown");
        assert!(
            html.contains("aa11") && html.contains("bb22"),
            "chain hashes shown"
        );
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "detail payload escaped"
        );
        assert!(!html.contains("<script>"), "no raw payload HTML");
    }
}
