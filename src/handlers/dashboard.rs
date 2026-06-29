//! The apex launcher: GET / renders the HOLDFAST dashboard.
//!
//! A heading ("HOLDFAST · Sovereign Cloud" / "Welcome, <email>") over a responsive grid of
//! service TILES. Each tile carries an inline-SVG icon, the service name, a one-line
//! description, a LIVE status pill, and links to the service's public subdomain. The
//! signed-in email comes from the gateway-injected `X-Auth-Email` (Portal does no login of
//! its own). Live status is pulled from Beacon and is resilient: an unreachable Beacon or
//! an unmapped component just renders an "unknown" pill — the page never errors.

use std::collections::HashMap;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Html;

use crate::auth;
use crate::catalog::CatalogEntry;
use crate::handlers::{
    coming_soon_pill, esc, icon_svg, status_pill, APP_CSS, SHIELD_SVG,
};
use crate::AppState;

const DASHBOARD_HTML: &str = include_str!("../../templates/dashboard.html");

/// `GET /` — the dashboard. Renders for any request the gateway forwards; the signed-in
/// email comes from the injected `X-Auth-Email`, and live status from the (cached) Beacon
/// snapshot.
pub async fn dashboard(State(state): State<AppState>, headers: HeaderMap) -> Html<String> {
    let email = auth::signed_in_email(&headers).unwrap_or_else(|| "operator".to_string());
    let statuses = state.cache.statuses(&state.config.beacon_url).await;
    Html(render_dashboard(&state.config.catalog, &email, &statuses))
}

fn render_dashboard(
    catalog: &[CatalogEntry],
    email: &str,
    statuses: &HashMap<String, String>,
) -> String {
    DASHBOARD_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{EMAIL}}", &esc(email))
        .replace("{{TILES}}", &render_tiles(catalog, statuses))
}

/// Render the responsive grid of service tiles.
fn render_tiles(catalog: &[CatalogEntry], statuses: &HashMap<String, String>) -> String {
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
            let status = statuses
                .get(&entry.component)
                .map(String::as_str)
                .unwrap_or("unknown");
            status_pill(status)
        };
        tiles.push_str(&format!(
            r#"<a class="tile" href="{url}">
  <div class="tile__top">
    <span class="tile__icon" aria-hidden="true">{icon}</span>
    {pill}
  </div>
  <div class="tile__name">{name}</div>
  <div class="tile__desc">{desc}</div>
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
