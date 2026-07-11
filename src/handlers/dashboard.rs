//! The apex command center: `GET /` renders the HOLDFAST operations dashboard.
//!
//! A sticky app-bar (shield + wordmark, signed-in email, logout), a brand-gradient hero with
//! a time-of-day greeting, a row of LIVE METRIC CARDS (systems online, host CPU/memory, audit
//! events, load), a SERVICES grid (one live-status card per catalog entry), and a RECENT
//! ACTIVITY feed of the latest audit events. The signed-in email comes from the
//! gateway-injected `X-Auth-Email` (Portal does no login of its own). The optional
//! internal-only management section is gated by the gateway-injected `X-Gateway-Zone`.
//!
//! Every live number is best-effort: the data comes from a single cached, concurrent fetch of
//! Beacon / Vitals / Watchtower ([`crate::snapshot`]). Any unreachable backend degrades its
//! own card/pill/feed to "—"/"unknown"/empty — the page NEVER errors or hangs.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use odyssey::{RuntimeOpts, WireOpts, WireSwap};
use serde::Deserialize;

use crate::auth;
use crate::catalog::CatalogEntry;
use crate::handlers::{
    app_css, esc, fmt_pct, greeting, icon_for, name_from_email, pct_width, rel_time,
    severity_dot_class, status_label, status_pill_class, SHIELD_SVG,
};
use crate::manifest::ProjectionIdentity;
use crate::snapshot::Snapshot;
use crate::watchtower::{Event, Verify};
use crate::AppState;

const DASHBOARD_HTML: &str = include_str!("../../templates/dashboard.html");
const HEADER_WIRE: &str = "x-wire";
const MGMT_SECTION_ID: &str = "infraops";
const MGMT_SECTION_LABEL: &str = "Infrastructure & Operations";
const MGMT_SECTION_STYLE: &str = "more";

#[derive(Deserialize, Default)]
pub struct DashQuery {
    #[serde(default)]
    q: String,
}

#[derive(Clone, Copy)]
struct CatalogView<'a> {
    public: &'a [CatalogEntry],
    internal: Option<&'a [CatalogEntry]>,
    public_projection: Option<&'a ProjectionIdentity>,
    estate_projection: Option<&'a ProjectionIdentity>,
}

#[derive(Clone, Copy)]
struct EstateSummary<'a> {
    public_surface_count: usize,
    internal_surface_count: Option<usize>,
    public_projection: Option<&'a ProjectionIdentity>,
    estate_projection: Option<&'a ProjectionIdentity>,
}

/// `GET /` — the command center. Renders for any request the gateway forwards; the signed-in
/// email comes from the injected `X-Auth-Email`, and every live figure from the (cached)
/// concurrent backend snapshot.
pub async fn dashboard(
    State(state): State<AppState>,
    Query(query): Query<DashQuery>,
    headers: HeaderMap,
) -> Response {
    let email = auth::signed_in_email(&headers).unwrap_or_else(|| "operator".to_string());
    let internal_zone = state.config.zone_verifier.is_internal(&headers);
    let wire_fragment = wire_request(&headers);
    let snap = state.cache.get(&state.config).await;
    let clock = clock();
    let internal_catalog = internal_zone.then(|| state.config.internal_catalog.as_slice());
    let body = render(
        CatalogView {
            public: &state.config.catalog,
            internal: internal_catalog,
            public_projection: state.config.public_projection.as_ref(),
            estate_projection: internal_zone
                .then_some(state.config.estate_projection.as_ref())
                .flatten(),
        },
        &email,
        &snap,
        clock,
        query.q.trim(),
        wire_fragment,
    );
    let mut response = Html(body).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        header::VARY,
        HeaderValue::from_static("X-Wire, X-Gateway-Zone, X-Gateway-Zone-Sig, X-Auth-Email"),
    );
    response
}

fn wire_request(headers: &HeaderMap) -> bool {
    matches!(
        headers
            .get(HEADER_WIRE)
            .and_then(|value| value.to_str().ok())
            .map(str::trim),
        Some("1")
    )
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
    view: CatalogView<'_>,
    email: &str,
    snap: &Snapshot,
    clock: (i64, u32),
    search_query: &str,
    wire_fragment: bool,
) -> String {
    let CatalogView {
        public: catalog,
        internal: internal_catalog,
        public_projection,
        estate_projection,
    } = view;
    let (now_secs, hour) = clock;
    let public_surface_count = catalog.len();
    let name = name_from_email(email);
    let initial = name
        .chars()
        .next()
        .unwrap_or('H')
        .to_uppercase()
        .to_string();
    let q = search_query.trim();
    let q_lower = q.to_lowercase();
    let filtered_catalog = if q.is_empty() {
        None
    } else {
        Some(filter_catalog(catalog, &q_lower))
    };
    let catalog = filtered_catalog.as_deref().unwrap_or(catalog);
    let internal_surface_count = internal_catalog.map(|entries| entries.len());
    let filtered_mgmt = if q.is_empty() {
        None
    } else {
        internal_catalog.map(|entries| filter_catalog(entries, &q_lower))
    };
    let mgmt = if q.is_empty() {
        internal_catalog
    } else {
        filtered_mgmt.as_deref()
    };
    let sidebar_nav = render_sidebar_nav(catalog, mgmt);
    let sections = render_dashboard_sections(catalog, mgmt, snap, q);
    let estate_live = render_estate_live(
        &name,
        snap,
        now_secs,
        hour,
        EstateSummary {
            public_surface_count,
            internal_surface_count,
            public_projection,
            estate_projection,
        },
    );
    if wire_fragment {
        return estate_live;
    }
    let runtime = odyssey::dynamic_scripts_with(RuntimeOpts::new().with_motion());
    DASHBOARD_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{INITIAL}}", &esc(&initial))
        .replace("{{NAME}}", &esc(&name))
        .replace("{{EMAIL}}", &esc(email))
        .replace("{{HEALTH_CHIP}}", &health_chip(snap))
        .replace("{{SIDEBAR_NAV}}", &sidebar_nav)
        .replace("{{ESTATE_LIVE}}", &estate_live)
        .replace("{{SECTIONS}}", &sections)
        .replace("{{SEARCH_VALUE}}", &esc(q))
        .replace("{{ODYSSEY_RUNTIME}}", runtime.as_str())
}

/// The sidebar catalog nav: one item per non-empty category (in [`SECTION_ORDER`]), with an
/// accent dot and a live app-count badge. The `data-spy` key matches the section element id so
/// the client-side scroll-spy can highlight the active section.
fn render_sidebar_nav(catalog: &[CatalogEntry], mgmt: Option<&[CatalogEntry]>) -> String {
    let mut out = String::new();
    for (key, label, apps) in grouped_catalog(catalog) {
        let count = apps.len();
        out.push_str(&format!(
            r##"<a class="nav__item" href="#{key}" data-spy="{key}"><span class="nav__dot nav__dot--{key}"></span><span class="nav__text">{label}</span><span class="nav__count">{count}</span></a>"##,
            key = key,
            label = esc(label),
            count = count,
        ));
    }
    if let Some(mgmt) = mgmt {
        if !mgmt.is_empty() {
            out.push_str(&format!(
                r##"<a class="nav__item" href="#{key}" data-spy="{key}"><span class="nav__dot nav__dot--{style}"></span><span class="nav__text">{label}</span><span class="nav__count">{count}</span></a>"##,
                key = MGMT_SECTION_ID,
                style = MGMT_SECTION_STYLE,
                label = esc(MGMT_SECTION_LABEL),
                count = mgmt.len(),
            ));
        }
    }
    out
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

fn incident_banner(snap: &Snapshot) -> String {
    let s = &snap.statuses;
    if !s.reached || s.total == 0 || s.up >= s.total {
        return String::new();
    }
    let issues: Vec<_> = s
        .components
        .iter()
        .filter(|c| c.status != "operational")
        .collect();
    let names = issues
        .iter()
        .take(3)
        .map(|c| esc(&c.name))
        .collect::<Vec<_>>()
        .join(", ");
    let more = if issues.len() > 3 {
        format!(" +{} more", issues.len() - 3)
    } else {
        String::new()
    };
    let variant = if issues.iter().any(|c| c.status == "down") {
        "incidentbar--down"
    } else {
        "incidentbar--warn"
    };
    format!(
        r#"<div class="incidentbar {variant}" role="status">
  <span class="incidentbar__dot" aria-hidden="true"></span>
  <p class="incidentbar__text"><strong>{affected} of {total} systems</strong> reporting issues: {names}{more}</p>
  <a class="incidentbar__link" href="https://status.w33d.xyz">View status &rarr;</a>
</div>"#,
        variant = variant,
        affected = s.total - s.up,
        total = s.total,
        names = names,
        more = more,
    )
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

/// The Odyssey Estate bridge. It is deliberately one independent, read-only region: Wire may
/// replace it without invalidating the catalog nodes held by the launcher/pin/palette runtime.
/// The same bytes are embedded in the full SSR document and returned for `X-Wire: 1`.
fn render_estate_live(
    name: &str,
    snap: &Snapshot,
    now_secs: i64,
    hour: u32,
    summary: EstateSummary<'_>,
) -> String {
    let EstateSummary {
        public_surface_count,
        internal_surface_count,
        public_projection,
        estate_projection,
    } = summary;
    let refresh = odyssey::link_with_wire(
        "/?refresh=1#estate-live",
        "Refresh snapshot",
        WireOpts::new("#estate-live")
            .select("#estate-live")
            .swap(WireSwap::Outer)
            .busy_label("Refreshing…")
            .success_message("Estate snapshot refreshed")
            .error_message("Could not refresh the Estate snapshot"),
    );
    format!(
        r#"<section class="estate-live" id="estate-live" role="region" aria-labelledby="estate-title">
{incident}
<div class="dash-hero">
  <p class="kicker">Odyssey Estate · Sovereign product fabric</p>
  <h1>{greeting}, <span class="grad">{name}</span></h1>
  <p class="lede">{sub}</p>
</div>
<section class="estate-deck" aria-label="Estate access planes">
  <div class="estate-deck__head">
    <div>
      <p class="estate-deck__eyebrow">Access map · read-only</p>
      <h2 id="estate-title">One estate, three trust paths</h2>
    </div>
    <div class="estate-deck__actions">
      {manifest}
      {signal}
      <span class="estate-refresh">{refresh}</span>
    </div>
  </div>
  {planes}
</section>
<div class="estate-observe">
  <section class="sys estate-health" id="sys" aria-labelledby="estate-health-title">
    <div class="sys__head">
      <h2 id="estate-health-title">Fleet health</h2>
      <span class="hint">Beacon · Vitals · Watchtower</span>
    </div>
    <div class="metrics">{metrics}</div>
  </section>
  <section class="sys estate-activity" id="activity" aria-labelledby="estate-activity-title">
    <div class="sys__head">
      <h2 id="estate-activity-title">Recent signals</h2>
      <span class="hint">Sealed audit events</span>
    </div>
    <div class="feedcard" data-motion-list>{activity}</div>
  </section>
</div>
</section>"#,
        incident = incident_banner(snap),
        greeting = greeting(hour),
        name = esc(name),
        sub = hero_sub(snap),
        manifest = render_manifest_signal(
            public_projection,
            estate_projection,
            public_surface_count + internal_surface_count.unwrap_or(0),
        ),
        signal = fleet_signal(snap),
        refresh = refresh,
        planes = render_access_planes(public_surface_count, internal_surface_count),
        metrics = render_metrics(snap),
        activity = render_activity(&snap.events, now_secs, internal_surface_count.is_some(),),
    )
}

fn render_manifest_signal(
    public: Option<&ProjectionIdentity>,
    estate: Option<&ProjectionIdentity>,
    surface_count: usize,
) -> String {
    let Some(public) = public else {
        return r#"<span class="estate-signal estate-signal--manifest"><span aria-hidden="true"></span>Built-in development catalog</span>"#.to_string();
    };
    let mut identities = vec![render_projection_identity("public", public)];
    if let Some(estate) = estate {
        identities.push(render_projection_identity("estate", estate));
    }
    format!(
        r#"<span class="estate-signal estate-signal--manifest" data-manifest-surface-count="{surface_count}"><span aria-hidden="true"></span>Manifest {release} · {surface_count} surfaces · {identities}</span>"#,
        release = esc(&public.release),
        identities = identities.join(" · "),
    )
}

fn render_projection_identity(audience: &str, identity: &ProjectionIdentity) -> String {
    let short: String = identity.fingerprint.chars().take(18).collect();
    format!(
        r#"<span data-manifest-audience="{audience}" data-manifest-release="{release}" data-manifest-fingerprint="{fingerprint}" title="{audience} projection · {release} · {fingerprint}">{audience} {short}</span>"#,
        audience = esc(audience),
        release = esc(&identity.release),
        fingerprint = esc(&identity.fingerprint),
        short = esc(&short),
    )
}

fn fleet_signal(snap: &Snapshot) -> String {
    let statuses = &snap.statuses;
    if statuses.reached && statuses.total > 0 {
        let class = if statuses.up == statuses.total {
            "estate-signal--ok"
        } else {
            "estate-signal--warn"
        };
        return format!(
            r#"<span class="estate-signal {class}" role="status"><span aria-hidden="true"></span>{up}/{total} operational</span>"#,
            class = class,
            up = statuses.up,
            total = statuses.total,
        );
    }
    r#"<span class="estate-signal" role="status"><span aria-hidden="true"></span>Snapshot syncing</span>"#
        .to_string()
}

/// Access-plane copy comes only from the configured public catalog, the exact gateway-attested
/// zone, and the Estate projection. The external view never receives management URLs.
fn render_access_planes(
    public_surface_count: usize,
    internal_surface_count: Option<usize>,
) -> String {
    let (private_value, private_copy, private_state, private_class) = match internal_surface_count {
        Some(count) => (
            format!("{count} management surfaces"),
            "Gateway attests the internal zone; WireGuard-only consoles are available below.",
            "Internal zone",
            " estate-plane--connected",
        ),
        None => (
            "WireGuard required".to_string(),
            "Management hostnames stay hidden until the gateway attests an internal connection.",
            "Restricted",
            "",
        ),
    };
    format!(
        r#"<div class="estate-planes">
  <article class="estate-plane estate-plane--public" data-motion-enter>
    <p class="estate-plane__rail"><span>01</span>Public gateway</p>
    <h3>{public_count} product surfaces</h3>
    <p>Internet-routable catalog entries. Each product keeps its own authentication policy.</p>
    <span class="estate-plane__state"><span aria-hidden="true"></span>Routed catalog</span>
  </article>
  <article class="estate-plane estate-plane--status" data-motion-enter>
    <p class="estate-plane__rail"><span>02</span>Open status</p>
    <h3>Anonymous, read-only</h3>
    <p><a href="https://status.w33d.xyz">status.w33d.xyz</a> stays publicly readable; no Portal identity or WireGuard connection is required.</p>
    <span class="estate-plane__state"><span aria-hidden="true"></span>Public</span>
  </article>
  <article class="estate-plane estate-plane--private{private_class}" data-motion-enter>
    <p class="estate-plane__rail"><span>03</span>WireGuard plane</p>
    <h3>{private_value}</h3>
    <p>{private_copy}</p>
    <span class="estate-plane__state"><span aria-hidden="true"></span>{private_state}</span>
  </article>
</div>"#,
        public_count = public_surface_count,
        private_class = private_class,
        private_value = private_value,
        private_copy = private_copy,
        private_state = private_state,
    )
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
        let cls = if s.up == s.total {
            "tag tag-ok"
        } else {
            "tag tag-warn"
        };
        let word = if s.up == s.total {
            "All operational"
        } else {
            "Degraded"
        };
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
        Some(w) => format!(r#"<div class="metric__bar"><span style="width:{w:.0}%"></span></div>"#),
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
    ("comms", "Communication"),
    ("content", "Content & Knowledge"),
    ("ident", "Identity & Security"),
    ("obs", "Observability"),
    ("ai", "AI & Assistants"),
    ("dev", "Developer & Platform"),
    ("more", "Platform & Tools"),
];
const MIN_SECTION: usize = 3;

/// Map a tile's display name to its section key. Unknown names land in "more" so a newly
/// added service still renders cleanly without a code change.
fn category_key(entry: &CatalogEntry) -> &'static str {
    match entry.category.as_str() {
        "communication" => return "comms",
        "content" => return "content",
        "identity" => return "ident",
        "observability" => return "obs",
        "ai" => return "ai",
        "developer" => return "dev",
        "platform" => return "more",
        _ => {}
    }
    match entry.name.as_str() {
        "Identity" | "Authorization" | "Directory" | "Audit" | "Vault" | "Threat Intel"
        | "Intel" | "Canary" | "Authz" | "People" | "Pulse" | "Risk" | "Sigil" | "SPIFFE"
        | "Crucible" | "Detonate" | "Phantom" | "Purple" | "Guard" => "ident",
        "Blog" | "Forum" | "Wiki" | "Pastefire" | "Paste" | "Search" | "Drive" | "Comments" => {
            "content"
        }
        "Mail" | "Chat" | "Notifications" | "Notify" | "Inbox" | "Calendar" | "Feeds" | "Clips"
        | "Social" => "comms",
        "Status" | "Vitals" | "Audit log" | "Logs" | "Sift" | "RCA" | "Traces" | "Filament"
        | "Augur" => "obs",
        "Assistant" | "AI Gateway" | "Multica" | "Relay" | "Grimoire" | "Familiar" | "Warden"
        | "Cascade" => "ai",
        "Git" | "Registry" | "Events" | "Jobs" | "Backup" | "Lodestar" | "DNS" | "Ripple"
        | "Eddy" | "Edge" | "Anvil" | "CI" | "Atlas" | "Mycelium" | "Mesh" | "Skiff" | "Deploy"
        | "Estuary" | "Egress" | "VPN enrollment" => "dev",
        _ => "more",
    }
}

fn grouped_catalog<'a>(
    catalog: &'a [CatalogEntry],
) -> Vec<(&'static str, &'static str, Vec<&'a CatalogEntry>)> {
    let mut buckets: Vec<(&'static str, &'static str, Vec<&'a CatalogEntry>)> = SECTION_ORDER
        .iter()
        .map(|(key, label)| (*key, *label, Vec::new()))
        .collect();
    for entry in catalog {
        let key = category_key(entry);
        if let Some((_, _, apps)) = buckets
            .iter_mut()
            .find(|(bucket_key, _, _)| *bucket_key == key)
        {
            apps.push(entry);
        }
    }

    let mut out = Vec::new();
    let mut more = Vec::new();
    let more_label = SECTION_ORDER
        .iter()
        .find(|(key, _)| *key == "more")
        .map(|(_, label)| *label)
        .unwrap_or("Platform & Tools");
    for (key, label, apps) in buckets {
        if key == "more" {
            more.extend(apps);
        } else if apps.len() >= MIN_SECTION {
            out.push((key, label, apps));
        } else {
            more.extend(apps);
        }
    }
    if !more.is_empty() {
        out.push(("more", more_label, more));
    }
    out
}

fn filter_catalog(catalog: &[CatalogEntry], q: &str) -> Vec<CatalogEntry> {
    catalog
        .iter()
        .filter(|entry| {
            entry.name.to_lowercase().contains(q) || entry.description.to_lowercase().contains(q)
        })
        .cloned()
        .collect()
}

/// Render the app chiclets grouped into the fixed sections (Okta end-user dashboard layout).
fn render_sections(catalog: &[CatalogEntry], snap: &Snapshot) -> String {
    let mut out = String::new();
    for (key, label, apps) in grouped_catalog(catalog) {
        out.push_str(&render_app_section(key, key, label, &apps, snap));
    }
    out
}

fn render_dashboard_sections(
    catalog: &[CatalogEntry],
    mgmt: Option<&[CatalogEntry]>,
    snap: &Snapshot,
    search_query: &str,
) -> String {
    let mgmt_empty = mgmt.is_none_or(|entries| entries.is_empty());
    if catalog.is_empty() && mgmt_empty {
        if search_query.is_empty() {
            return r#"<div class="empty">No apps are configured.</div>"#.to_string();
        }
        return format!(
            r#"<div class="empty">No apps match &ldquo;{}&rdquo;.</div>"#,
            esc(search_query)
        );
    }
    let mut out = render_sections(catalog, snap);
    if let Some(mgmt) = mgmt {
        if !mgmt.is_empty() {
            let apps: Vec<&CatalogEntry> = mgmt.iter().collect();
            out.push_str(&render_app_section(
                MGMT_SECTION_ID,
                MGMT_SECTION_STYLE,
                MGMT_SECTION_LABEL,
                &apps,
                snap,
            ));
        }
    }
    out
}

fn render_app_section(
    section_id: &str,
    style_key: &str,
    label: &str,
    apps: &[&CatalogEntry],
    snap: &Snapshot,
) -> String {
    let mut out = format!(
        r#"<section class="appsec appsec--{style}" id="{id}" data-section><h2 class="appsec__title"><span class="pip"></span><span class="nm">{label}</span><span class="ct">{count} apps</span><span class="ln"></span></h2><div class="appgrid">"#,
        style = style_key,
        id = section_id,
        label = esc(label),
        count = apps.len(),
    );
    for entry in apps {
        out.push_str(&render_app(entry, snap));
    }
    out.push_str("</div></section>");
    out
}

/// One app chiclet: a category-tinted icon tile, the app name + description, and a live status
/// dot (top-right). Coming-soon services show a "Soon" badge and an accent dot.
fn render_app(entry: &CatalogEntry, snap: &Snapshot) -> String {
    let cat = category_key(entry);
    let soon_badge = if entry.coming_soon {
        r#"<span class="app__soon">Soon</span>"#.to_string()
    } else {
        String::new()
    };
    let status_span = if entry.coming_soon {
        String::new()
    } else {
        match snap.statuses.status_of(&entry.component) {
            "degraded" | "down" => {
                let status = snap.statuses.status_of(&entry.component);
                let title = status_label(status);
                format!(
                    r#"<span class="app__status {dot}" title="{title}" aria-label="{title}"></span>"#,
                    dot = status_pill_class(status),
                    title = esc(title),
                )
            }
            _ => String::new(),
        }
    };
    // Lowercased name+description backs the client-side app search filter.
    let data_name = esc(&format!("{} {}", entry.name, entry.description).to_lowercase());
    let app_id = esc(&entry.url);
    let product_id = if entry.id.is_empty() {
        app_id.clone()
    } else {
        esc(&entry.id)
    };
    let profile = if entry.profile.is_empty() {
        String::new()
    } else {
        format!(r#" data-ody-profile="{}""#, esc(&entry.profile))
    };
    let pin_label = esc(&format!("Pin {}", entry.name));
    let tooltip = if entry.description.is_empty() {
        esc(&entry.name)
    } else {
        esc(&format!("{} — {}", entry.name, entry.description))
    };
    format!(
        r#"<div class="appwrap" data-app-id="{id}" data-product-id="{product_id}">
<a class="app app--{cat}" href="{url}" title="{tooltip}" data-name="{dn}" data-app-id="{id}" data-product-id="{product_id}"{profile}>
  {soon}
  {status}
  <span class="app__icon" aria-hidden="true">{icon}</span>
  <span class="app__name">{name}</span>
  <span class="app__desc">{desc}</span>
</a>
<button class="app__pin" type="button" data-pin-button data-app-id="{id}" aria-pressed="false" aria-label="{pin_label}" title="{pin_label}">
  {pin_icon}
</button>
</div>"#,
        id = app_id,
        product_id = product_id,
        profile = profile,
        cat = cat,
        url = esc(&entry.url),
        tooltip = tooltip,
        dn = data_name,
        soon = soon_badge,
        status = status_span,
        icon = icon_for(&entry.name, &entry.icon),
        name = esc(&entry.name),
        desc = esc(&entry.description),
        pin_label = pin_label,
        pin_icon = ICON_STAR,
    )
}

// --- Recent activity feed --------------------------------------------------------------

/// Render the recent-activity feed from the most recent audit events. Empty / unreachable
/// Watchtower shows a calm placeholder rather than an error.
fn render_activity(events: &[Event], now_secs: i64, disclose_target: bool) -> String {
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
        let target = if !disclose_target || ev.target.trim().is_empty() {
            String::new()
        } else {
            format!("{} · ", esc(&ev.target))
        };
        out.push_str(&format!(
            r#"<div class="feed__item">
  <span class="feed__dot {sev}" aria-hidden="true"></span>
  <div class="feed__body">
    <div class="feed__line"><span class="feed__action">{action}</span> <span class="feed__actor">{actor}</span></div>
    <div class="feed__meta">{target}<span data-spark-reltime data-ts="{ts}">{when}</span></div>
  </div>
</div>"#,
            sev = severity_dot_class(&ev.severity),
            action = esc(&action),
            actor = esc(&actor),
            target = target,
            ts = ev.ts / 1_000,
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
const ICON_STAR: &str = r##"<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="m12 3 2.7 5.47 6.03.88-4.36 4.25 1.03 6-5.4-2.84-5.4 2.84 1.03-6-4.36-4.25 6.03-.88L12 3Z"/></svg>"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_document_embeds_the_exact_wire_fragment() {
        let catalog = crate::catalog::default_catalog();
        let snapshot = Snapshot::default();
        let full = render(
            CatalogView {
                public: &catalog,
                internal: None,
                public_projection: None,
                estate_projection: None,
            },
            "alice@holdfast.local",
            &snapshot,
            (1_700_000_000, 8),
            "",
            false,
        );
        let fragment = render(
            CatalogView {
                public: &catalog,
                internal: None,
                public_projection: None,
                estate_projection: None,
            },
            "alice@holdfast.local",
            &snapshot,
            (1_700_000_000, 8),
            "",
            true,
        );

        assert!(
            fragment.starts_with(r#"<section class="estate-live" id="estate-live" role="region""#)
        );
        assert!(
            full.contains(&fragment),
            "full SSR uses the fragment renderer byte-for-byte"
        );
        assert!(!fragment.contains(r#"id="appsections""#));
        assert!(!fragment.contains("data-pin-button"));
        assert!(!fragment.contains(r#"id="cmdpalette""#));
        assert!(full.contains("odyssey-wire v1"));
        assert!(full.contains("odyssey-spark v1"));
        assert!(full.contains("odyssey-motion v1"));
    }

    #[test]
    fn external_access_map_describes_but_does_not_disclose_management_surfaces() {
        let external = render_access_planes(22, None);
        assert!(external.contains("22 product surfaces"));
        assert!(external.contains("Anonymous, read-only"));
        assert!(external.contains("https://status.w33d.xyz"));
        assert!(external.contains("WireGuard required"));
        assert!(!external.contains("management surfaces"));
        assert!(!external.contains("vault.w33d.xyz"));

        let internal = render_access_planes(22, Some(27));
        assert!(internal.contains("27 management surfaces"));
        assert!(internal.contains("Internal zone"));
        assert!(
            !internal.contains("vault.w33d.xyz"),
            "summary never invents a route list"
        );
    }

    #[test]
    fn manifest_signal_discloses_only_the_identities_for_the_current_view() {
        let public = ProjectionIdentity {
            release: "1.0.0".to_string(),
            fingerprint: format!("sha256:{}", "a".repeat(64)),
        };
        let estate = ProjectionIdentity {
            release: "1.0.0".to_string(),
            fingerprint: format!("sha256:{}", "b".repeat(64)),
        };

        let external = render_manifest_signal(Some(&public), None, 23);
        assert!(external.contains(r#"data-manifest-surface-count="23""#));
        assert!(external.contains(r#"data-manifest-audience="public""#));
        assert!(external.contains(&public.fingerprint));
        assert!(!external.contains(r#"data-manifest-audience="estate""#));
        assert!(!external.contains(&estate.fingerprint));

        let internal = render_manifest_signal(Some(&public), Some(&estate), 50);
        assert!(internal.contains(r#"data-manifest-surface-count="50""#));
        assert!(internal.contains(r#"data-manifest-audience="public""#));
        assert!(internal.contains(r#"data-manifest-audience="estate""#));
        assert!(internal.contains(&public.fingerprint));
        assert!(internal.contains(&estate.fingerprint));
    }

    #[test]
    fn only_the_exact_wire_header_requests_a_fragment() {
        let mut headers = HeaderMap::new();
        assert!(!wire_request(&headers));
        headers.insert(HEADER_WIRE, HeaderValue::from_static("true"));
        assert!(!wire_request(&headers));
        headers.insert(HEADER_WIRE, HeaderValue::from_static("1"));
        assert!(wire_request(&headers));
    }
}
