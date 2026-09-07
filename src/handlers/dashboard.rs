//! The apex launcher: `GET /` renders the Steadholme Portal "command canvas".
//!
//! The page is command-first: a single search field, the locally remembered recent/pinned
//! services, a live Fleet + Host summary, and the catalog as category clusters of icon + name
//! tiles. Every visible string is a name, a value or an action — no eyebrows, coordinates,
//! source attributions or counts. The signed-in email comes from the gateway-injected
//! `X-Auth-Email` (Portal does no login of its own). The optional internal-only management
//! cluster is gated by the gateway-injected `X-Gateway-Zone`.
//!
//! Every live number is best-effort: the data comes from a single cached, concurrent fetch of
//! Beacon / Vitals / Watchtower ([`crate::snapshot`]). Any unreachable backend degrades its
//! own figure to "—"/"unknown" — the page NEVER errors or hangs.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use odyssey::{RuntimeOpts, WireOpts, WireSwap};
use serde::Deserialize;

use crate::auth;
use crate::beacon::Statuses;
use crate::catalog::CatalogEntry;
use crate::handlers::{
    esc, fmt_count, fmt_pct, icon_for, name_from_email, pct_width, status_label, status_pill,
    status_pill_class, SHIELD_SVG,
};
use crate::snapshot::Snapshot;
use crate::AppState;

const DASHBOARD_HTML: &str = include_str!("../../templates/dashboard.html");
const HEADER_WIRE: &str = "x-wire";
const MGMT_SECTION_ID: &str = "infraops";
const MGMT_SECTION_LABEL: &str = "Internal";
/// How many non-operational components the Fleet card lists by name before folding the rest.
const FLEET_ISSUE_LIMIT: usize = 4;

#[derive(Deserialize, Default)]
pub struct DashQuery {
    #[serde(default)]
    q: String,
}

#[derive(Clone, Copy)]
struct CatalogView<'a> {
    public: &'a [CatalogEntry],
    internal: Option<&'a [CatalogEntry]>,
}

/// `GET /` — the launcher. Renders for any request the gateway forwards; the signed-in email
/// comes from the injected `X-Auth-Email`, and every live figure from the (cached) concurrent
/// backend snapshot.
pub async fn dashboard(
    State(state): State<AppState>,
    Query(query): Query<DashQuery>,
    headers: HeaderMap,
) -> Response {
    let email = auth::signed_in_email(&headers).unwrap_or_else(|| "operator".to_string());
    let internal_zone = state.config.zone_verifier.is_internal(&headers);
    let wire_fragment = wire_request(&headers);
    let snap = state.cache.get(&state.config).await;
    let statuses = if internal_zone {
        &snap.operator_statuses
    } else {
        &snap.public_statuses
    };
    let internal_catalog = internal_zone.then(|| state.config.internal_catalog.as_slice());
    let body = render(
        CatalogView {
            public: &state.config.catalog,
            internal: internal_catalog,
        },
        &email,
        &snap,
        statuses,
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

fn render(
    view: CatalogView<'_>,
    email: &str,
    snap: &Snapshot,
    statuses: &Statuses,
    search_query: &str,
    wire_fragment: bool,
) -> String {
    let CatalogView {
        public: catalog,
        internal: internal_catalog,
    } = view;
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
    // The live region is ONE independent read-only block: Wire may replace it without
    // invalidating the catalog nodes held by the launcher/pin/palette runtime. The same bytes
    // are embedded in the full document and returned alone for `X-Wire: 1`.
    let live = render_live(snap, statuses, internal_catalog.is_some());
    if wire_fragment {
        return live;
    }
    let sections = render_dashboard_sections(catalog, mgmt, statuses, q);
    let runtime = odyssey::dynamic_scripts_with(RuntimeOpts::new().with_motion());
    DASHBOARD_HTML
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{INITIAL}}", &esc(&initial))
        .replace("{{NAME}}", &esc(&name))
        .replace("{{EMAIL}}", &esc(email))
        .replace("{{HEALTH_CHIP}}", &health_chip(statuses))
        .replace("{{LIVE}}", &live)
        .replace("{{SECTIONS}}", &sections)
        .replace("{{SEARCH_VALUE}}", &esc(q))
        .replace("{{ODYSSEY_RUNTIME}}", runtime.as_str())
}

/// The top-row fleet chip: "N/M up" tinted by whether everything is up. Nothing is rendered
/// until Beacon first reports — there is no value to show.
fn health_chip(s: &Statuses) -> String {
    if s.reached && s.total > 0 {
        let cls = if s.up == s.total { "is-ok" } else { "is-warn" };
        format!(
            r#"<span class="healthchip {cls}"><span class="dot"></span>{up}/{total} up</span>"#,
            cls = cls,
            up = s.up,
            total = s.total,
        )
    } else {
        String::new()
    }
}

// --- Live region: Fleet + Host ----------------------------------------------------------

/// Overall fleet state token for the live region: unknown until Beacon reports, operational
/// only when every component is up, down when any component is down, else degraded.
fn overall_state(statuses: &Statuses) -> &'static str {
    if !statuses.reached || statuses.total == 0 {
        "unknown"
    } else if statuses.up == statuses.total {
        "operational"
    } else if statuses.components.iter().any(|c| c.status == "down") {
        "down"
    } else {
        "degraded"
    }
}

fn render_live(snap: &Snapshot, statuses: &Statuses, internal: bool) -> String {
    let refresh = odyssey::link_with_wire(
        "/?refresh=1#estate-live",
        "Refresh",
        WireOpts::new("#estate-live")
            .select("#estate-live")
            .swap(WireSwap::Outer)
            .busy_label("Refreshing…")
            .success_message("Refreshed")
            .error_message("Could not refresh"),
    );
    format!(
        r#"<section class="live" id="estate-live" role="region" aria-label="Live" data-state="{overall}" data-up="{up}" data-total="{total}" data-access-scope="{access_scope}">
{fleet}
{host}
</section>"#,
        overall = overall_state(statuses),
        up = statuses.up,
        total = statuses.total,
        access_scope = if internal { "internal" } else { "public" },
        fleet = render_fleet_card(statuses, refresh.as_str()),
        host = render_host_card(snap),
    )
}

/// The Fleet card: one dot per Beacon component on a ring, the up/total readout in the
/// centre, and the non-operational components listed by name with a status pill.
fn render_fleet_card(statuses: &Statuses, refresh: &str) -> String {
    let reached = statuses.reached && statuses.total > 0;
    let mut dots = String::new();
    let mut issues = String::new();
    if reached {
        for (index, component) in statuses.components.iter().enumerate() {
            let tone = match component.status.as_str() {
                "operational" => "ok",
                "degraded" => "warn",
                "down" => "down",
                _ => "unknown",
            };
            dots.push_str(&format!(
                r#"<span class="ring__dot ring__dot--{tone}" style="--i:{index}" title="{name} · {label}"></span>"#,
                tone = tone,
                index = index,
                name = esc(&component.name),
                label = status_label(&component.status),
            ));
        }
        let troubled: Vec<_> = statuses
            .components
            .iter()
            .filter(|c| c.status != "operational")
            .collect();
        if troubled.is_empty() {
            issues.push_str(&format!(
                r#"<li class="issues__ok">{check}<span>{total} operational</span></li>"#,
                check = ICON_CHECK,
                total = statuses.total,
            ));
        } else {
            for component in troubled.iter().take(FLEET_ISSUE_LIMIT) {
                issues.push_str(&format!(
                    r#"<li><span class="issues__name">{name}</span>{pill}</li>"#,
                    name = esc(&component.name),
                    pill = status_pill(&component.status),
                ));
            }
            if troubled.len() > FLEET_ISSUE_LIMIT {
                issues.push_str(&format!(
                    r#"<li class="issues__more">+{more}</li>"#,
                    more = troubled.len() - FLEET_ISSUE_LIMIT,
                ));
            }
        }
    } else {
        issues.push_str(r#"<li class="issues__ok"><span>—</span></li>"#);
    }
    let centre = if reached {
        format!(
            "<b>{up}/{total}</b><small>up</small>",
            up = statuses.up,
            total = statuses.total
        )
    } else {
        "<b>—</b>".to_string()
    };
    format!(
        r#"<article class="pcard pcard--fleet" data-motion-enter>
  <header class="pcard__head">
    <h2>Fleet</h2>
    <span class="pcard__tools">{refresh}<a href="https://status.w33d.xyz">Status {ext}</a></span>
  </header>
  <div class="fleet">
    <div class="ring" style="--n:{n}" aria-hidden="true"><span class="ring__orbit"></span>{dots}<span class="ring__centre">{centre}</span></div>
    <ul class="issues">{issues}</ul>
  </div>
</article>"#,
        refresh = refresh,
        ext = ICON_EXTERNAL,
        n = statuses.components.len().max(1),
        dots = dots,
        centre = centre,
        issues = issues,
    )
}

/// The Host card: three vertical meters (CPU / memory / load) from Vitals, the recent
/// Watchtower event count, and the sealed-chain verdict.
fn render_host_card(snap: &Snapshot) -> String {
    let cpu = snap.metrics.cpu_pct;
    let mem = snap.metrics.mem_pct;
    let load = snap.metrics.load1;
    let meters = [
        meter(
            "CPU",
            &fmt_pct(cpu),
            cpu.map(pct_width_opt),
            gauge_state(cpu),
        ),
        meter(
            "Memory",
            &fmt_pct(mem),
            mem.map(pct_width_opt),
            gauge_state(mem),
        ),
        meter(
            "Load",
            &load_value(load),
            load.map(load_width),
            load_state(load),
        ),
    ]
    .concat();
    // Reached-but-broken is an integrity failure, not a degradation: it maps to "down".
    let chain_state = if !snap.verify.reached {
        "unknown"
    } else if snap.verify.ok {
        "operational"
    } else {
        "down"
    };
    let chain = if snap.verify.reached {
        format!(
            r#"{check}<span class="chain__count">{count} sealed</span><span class="chain__word">{word}</span>"#,
            check = ICON_CHECK,
            count = fmt_count(snap.verify.count),
            word = if snap.verify.ok {
                "chain verified"
            } else {
                "integrity broken"
            },
        )
    } else {
        format!(
            r#"{check}<span class="chain__count">—</span>"#,
            check = ICON_CHECK
        )
    };
    format!(
        r#"<article class="pcard pcard--host" data-motion-enter>
  <header class="pcard__head">
    <h2>Host</h2>
    <span class="pcard__aside"><b>{events}</b>events</span>
  </header>
  <div class="meters">{meters}</div>
  <p class="chain" data-state="{chain_state}">{chain}</p>
</article>"#,
        events = fmt_count(snap.events.len()),
        meters = meters,
        chain_state = chain_state,
        chain = chain,
    )
}

fn meter(label: &str, value: &str, fill: Option<f64>, state: &str) -> String {
    format!(
        r#"<div class="meter" data-state="{state}"><span class="meter__value">{value}</span><span class="meter__track"><span class="meter__fill" style="height:{fill:.0}%"></span></span><span class="meter__label">{label}</span></div>"#,
        state = state,
        value = esc(value),
        fill = fill.unwrap_or(0.0),
        label = esc(label),
    )
}

fn gauge_state(value: Option<f64>) -> &'static str {
    match value {
        Some(v) if v >= 90.0 => "down",
        Some(v) if v >= 75.0 => "warn",
        Some(_) => "ok",
        None => "unknown",
    }
}

/// A 1-minute load average drawn against a two-core-equivalent scale: 1.0 fills half.
fn load_width(load1: f64) -> f64 {
    (load1 * 50.0).clamp(0.0, 100.0)
}

fn load_state(load1: Option<f64>) -> &'static str {
    match load1 {
        Some(v) if v >= 2.0 => "down",
        Some(v) if v >= 1.0 => "warn",
        Some(_) => "ok",
        None => "unknown",
    }
}

fn load_value(load1: Option<f64>) -> String {
    match load1 {
        Some(v) => format!("{v:.2}"),
        None => "—".to_string(),
    }
}

/// `pct_width` already clamps; this thin wrapper keeps the `.map` closures readable.
fn pct_width_opt(v: f64) -> f64 {
    pct_width(Some(v))
}

// --- Service catalog, grouped into category clusters ------------------------------------

/// The fixed cluster order + display label. A catalog entry is placed by [`category_key`];
/// the cluster is rendered only when at least one app falls in it.
const SECTION_ORDER: &[(&str, &str)] = &[
    ("comms", "Communication"),
    ("content", "Content & Knowledge"),
    ("ident", "Identity & Security"),
    ("obs", "Observability"),
    ("ai", "AI & Assistants"),
    ("dev", "Developer & Platform"),
    ("more", "Platform & Tools"),
];
const INTERNAL_SECTION_ORDER: &[(&str, &str)] = &[
    ("observe", "Observe"),
    ("protect", "Protect"),
    ("ship", "Ship"),
    ("network", "Network"),
    ("recover", "Recover"),
];

/// Map a tile's display name to its cluster key. Unknown names land in "more" so a newly
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
        "Identity" | "Account" | "Access" | "Authorization" | "Directory" | "Audit" | "Vault"
        | "Threat Intel" | "Intel" | "Canary" | "Authz" | "People" | "Pulse" | "Risk" | "Sigil"
        | "SPIFFE" | "Crucible" | "Detonate" | "Phantom" | "Purple" | "Guard" => "ident",
        "Blog" | "Forum" | "Wiki" | "Pastefire" | "Paste" | "Search" | "Drive" | "Comments"
        | "CanvasMind" | "Heartlines" => "content",
        "Mail" | "Chat" | "Notifications" | "Notify" | "Inbox" | "Calendar" | "Feeds" | "Clips"
        | "Social" => "comms",
        "Status" | "Vitals" | "Audit log" | "Logs" | "Sift" | "RCA" | "Traces" | "Filament"
        | "Augur" => "obs",
        "Assistant" | "AI Gateway" | "Multica" | "ComfyUI" | "Studio" | "Relay" | "Grimoire"
        | "Familiar" | "Warden" | "Cascade" => "ai",
        "Git" | "Registry" | "Events" | "Jobs" | "Backup" | "Lodestar" | "DNS" | "Ripple"
        | "Eddy" | "Edge" | "Anvil" | "CI" | "Atlas" | "Mycelium" | "Mesh" | "Skiff" | "Deploy"
        | "Estuary" | "Egress" | "VPN enrollment" | "Cistern" | "Sites" | "Odyssey" => "dev",
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
    buckets
        .into_iter()
        .filter(|(_, _, apps)| !apps.is_empty())
        .collect()
}

fn internal_group_key(entry: &CatalogEntry) -> &'static str {
    match entry.name.as_str() {
        "Audit log" | "Vitals" | "Logs" | "Traces" | "RCA" => "observe",
        "Authorization" | "Directory" | "Vault" | "SPIFFE" | "Risk" | "Intel" | "Guard"
        | "Purple" | "Detonate" | "Canary" => "protect",
        "CI" | "Deploy" | "Sites" | "Events" | "Jobs" | "Atlas" => "ship",
        "DNS" | "Egress" | "Mesh" | "Edge" | "VPN enrollment" => "network",
        "Backup" => "recover",
        _ => "protect",
    }
}

fn grouped_internal_catalog(
    catalog: &[CatalogEntry],
) -> Vec<(&'static str, &'static str, Vec<&CatalogEntry>)> {
    let mut buckets: Vec<_> = INTERNAL_SECTION_ORDER
        .iter()
        .map(|(key, label)| (*key, *label, Vec::new()))
        .collect();
    for entry in catalog {
        let key = internal_group_key(entry);
        if let Some((_, _, apps)) = buckets
            .iter_mut()
            .find(|(candidate, _, _)| *candidate == key)
        {
            apps.push(entry);
        }
    }
    buckets
        .into_iter()
        .filter(|(_, _, apps)| !apps.is_empty())
        .collect()
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

fn render_dashboard_sections(
    catalog: &[CatalogEntry],
    mgmt: Option<&[CatalogEntry]>,
    statuses: &Statuses,
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
    let mut out = String::new();
    for (key, label, apps) in grouped_catalog(catalog) {
        out.push_str(&render_cluster(key, label, &apps, statuses));
    }
    if let Some(mgmt) = mgmt {
        if !mgmt.is_empty() {
            out.push_str(&format!(
                r#"<section class="cluster cluster--internal" id="{id}" data-access-scope="internal" data-category="{label}" aria-labelledby="{id}-title" data-motion-enter><header class="cluster__head"><span class="cluster__dot" aria-hidden="true"></span><h2 id="{id}-title">{label}</h2><span class="cluster__lock" aria-hidden="true">{lock}</span><span class="pill pill-neutral">VPN</span></header><div class="cluster__groups">"#,
                id = MGMT_SECTION_ID,
                label = MGMT_SECTION_LABEL,
                lock = ICON_SHIELD,
            ));
            for (key, label, apps) in grouped_internal_catalog(mgmt) {
                out.push_str(&render_subcluster(
                    &format!("{MGMT_SECTION_ID}-{key}"),
                    label,
                    &apps,
                    statuses,
                ));
            }
            out.push_str("</div></section>");
        }
    }
    out
}

/// One public category cluster: a dot in the category colour, the name, and the tile grid.
fn render_cluster(key: &str, label: &str, apps: &[&CatalogEntry], statuses: &Statuses) -> String {
    let mut out = format!(
        r#"<section class="cluster cluster--{key}" id="{key}" data-section data-access-scope="public" aria-labelledby="{key}-title" data-category="{label}" data-motion-enter><header class="cluster__head"><span class="cluster__dot" aria-hidden="true"></span><h2 id="{key}-title">{label}</h2></header><div class="cluster__grid">"#,
        key = key,
        label = esc(label),
    );
    for entry in apps {
        out.push_str(&render_app(entry, statuses, "public"));
    }
    out.push_str("</div></section>");
    out
}

/// One group inside the internal cluster (Observe / Protect / Ship / Network / Recover).
fn render_subcluster(id: &str, label: &str, apps: &[&CatalogEntry], statuses: &Statuses) -> String {
    let mut out = format!(
        r#"<section class="subcluster" id="{id}" data-section data-access-scope="internal" data-category="{cat}" aria-labelledby="{id}-title"><h3 id="{id}-title">{label}</h3><div class="cluster__grid">"#,
        id = id,
        cat = MGMT_SECTION_LABEL,
        label = esc(label),
    );
    for entry in apps {
        out.push_str(&render_app(entry, statuses, "internal"));
    }
    out.push_str("</div></section>");
    out
}

/// One tile: a category-tinted icon and the name. A degraded/down component adds a status
/// ring on the icon; a coming-soon service shows a "Soon" tag instead. The description stays
/// in the DOM (visually hidden) for search, the palette and the drawer.
fn render_app(entry: &CatalogEntry, statuses: &Statuses, access_scope: &str) -> String {
    let cat = category_key(entry);
    let soon_badge = if entry.coming_soon {
        r#"<span class="app__soon">Soon</span>"#.to_string()
    } else {
        String::new()
    };
    let status_span = if entry.coming_soon {
        String::new()
    } else {
        match statuses.status_of(&entry.component) {
            "degraded" | "down" => {
                let status = statuses.status_of(&entry.component);
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
    let health = if entry.coming_soon {
        "soon"
    } else {
        statuses.status_of(&entry.component)
    };
    // Lowercased name+description backs the client-side search filter.
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
        r#"<div class="appwrap" data-app-id="{id}" data-product-id="{product_id}" data-health="{health}" data-access-scope="{access_scope}">
<a class="app app--{cat}" href="{url}" title="{tooltip}" data-name="{dn}" data-app-id="{id}" data-product-id="{product_id}" data-health="{health}" data-access-scope="{access_scope}"{profile}>
  <span class="app__icon" aria-hidden="true">{icon}</span>
  <span class="app__name">{name}</span>
  {status}{soon}
  <span class="app__desc">{desc}</span>
</a>
<button class="app__pin" type="button" data-pin-button data-app-id="{id}" aria-pressed="false" aria-label="{pin_label}" title="{pin_label}">
  {pin_icon}
</button>
</div>"#,
        id = app_id,
        product_id = product_id,
        health = health,
        access_scope = access_scope,
        profile = profile,
        cat = cat,
        url = esc(&entry.url),
        tooltip = tooltip,
        dn = data_name,
        status = status_span,
        soon = soon_badge,
        icon = icon_for(&entry.name, &entry.icon),
        name = esc(&entry.name),
        desc = esc(&entry.description),
        pin_label = pin_label,
        pin_icon = ICON_STAR,
    )
}

// --- Inline glyphs ---------------------------------------------------------------------

const ICON_STAR: &str = r##"<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="m12 3 2.7 5.47 6.03.88-4.36 4.25 1.03 6-5.4-2.84-5.4 2.84 1.03-6-4.36-4.25 6.03-.88L12 3Z"/></svg>"##;
const ICON_CHECK: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 12 5 5L20 7"/></svg>"##;
const ICON_EXTERNAL: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 4h6v6M20 4l-9 9"/><path d="M19 13v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h6"/></svg>"##;
const ICON_SHIELD: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V5l-8-3Z"/><path d="m9 12 2 2 4-4"/></svg>"##;

#[cfg(test)]
mod tests {
    use super::*;

    fn render_pair(wire: bool) -> String {
        let catalog = crate::catalog::default_catalog();
        let snapshot = Snapshot::default();
        render(
            CatalogView {
                public: &catalog,
                internal: None,
            },
            "alice@steadholme.local",
            &snapshot,
            &snapshot.public_statuses,
            "",
            wire,
        )
    }

    #[test]
    fn live_region_is_embedded_and_served_alone_for_wire() {
        let full = render_pair(false);
        let fragment = render_pair(true);

        assert!(fragment.starts_with(r#"<section class="live" id="estate-live" role="region""#));
        assert!(
            full.contains(&fragment),
            "the full document embeds the exact wire bytes"
        );
        assert!(!fragment.contains(r#"id="appsections""#));
        assert!(!fragment.contains("data-pin-button"));
        assert!(!fragment.contains(r#"id="cmdpalette""#));
        assert!(full.contains("odyssey-wire v1"));
        assert!(full.contains("odyssey-spark v1"));
        assert!(full.contains("odyssey-motion v1"));
    }

    #[test]
    fn tiles_carry_no_decorative_vocabulary() {
        let full = render_pair(false);
        assert!(full.contains(r#"<a class="app app--comms" href="https://mail.w33d.xyz""#));
        assert!(
            !full.contains("app__meta"),
            "category text is not repeated under tiles"
        );
        assert!(!full.contains("ody-index"), "no index codes");
        assert!(!full.contains("ody-coordinate"), "no coordinates");
        assert!(!full.contains("services</p>"), "no per-cluster counts");
    }

    #[test]
    fn unreached_backends_render_placeholders_not_errors() {
        let fragment = render_pair(true);
        assert!(fragment.contains(r#"data-state="unknown""#));
        assert!(fragment.contains(r#"<p class="chain" data-state="unknown">"#));
        assert!(fragment.contains(r#"<span class="chain__count">—</span>"#));
        assert!(fragment.contains(r#"<span class="meter__value">—</span>"#));
        assert!(!fragment.contains("awaiting"), "no narrated placeholders");
    }
}
