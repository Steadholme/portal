//! Beacon client: fetch the live component-status snapshot.
//!
//! The dashboard maps each catalog entry's `component` name to a status pill, and the metric
//! row shows a "systems online" count. Both come from Beacon's machine-readable snapshot at
//! `<BEACON_URL>/api/status`. Portal fetches the same contract independently from public and
//! operator projection endpoints, then selects one at the rendering trust boundary.
//!
//! RESILIENCE IS THE CONTRACT: every failure (DNS, connect, timeout, non-200, bad JSON)
//! collapses to an EMPTY snapshot. Missing components render an "unknown" pill and the count
//! shows "—", so a down or slow Beacon NEVER errors the dashboard.

use std::collections::HashMap;
use std::time::Duration;

use serde::Deserialize;

use crate::http;

/// Per-fetch budget. Beacon is in-network; keep it short so a stalled connection can never
/// tie a page load up for long.
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// The slice of Beacon's `/api/status` JSON we need: each component's name + status. Extra
/// fields (uptime, latency, incidents, overall) are ignored.
#[derive(Debug, Deserialize)]
struct BeaconStatus {
    #[serde(default)]
    components: Vec<BeaconComponent>,
}

#[derive(Debug, Deserialize)]
struct BeaconComponent {
    name: String,
    status: String,
    /// Rolling 24h uptime percentage (the operator console's HEALTH table shows it). Absent on
    /// older Beacons -> `None` -> rendered "—".
    #[serde(default)]
    uptime_24h: Option<f64>,
}

/// One component row for the operator console's per-service HEALTH table (name / status /
/// uptime), in the order Beacon reported them.
#[derive(Clone, Debug)]
pub struct Component {
    pub name: String,
    pub status: String,
    pub uptime_24h: Option<f64>,
}

/// A parsed Beacon snapshot: per-component statuses plus the operational rollup the
/// "systems online" metric card reads. An empty snapshot (`reached == false`) means Beacon
/// was unreachable — the dashboard then renders "unknown"/"—" everywhere.
#[derive(Clone, Debug, Default)]
pub struct Statuses {
    /// component name -> status token (`operational` | `degraded` | `down`).
    pub by_name: HashMap<String, String>,
    /// Ordered component rows (name / status / uptime) for the operator HEALTH table.
    pub components: Vec<Component>,
    /// Count of components reporting `operational`.
    pub up: usize,
    /// Total components Beacon reported.
    pub total: usize,
    /// Whether Beacon answered with parseable JSON at all (drives "—" vs a real count).
    pub reached: bool,
}

impl Statuses {
    /// Status token for one component, or `"unknown"` when Beacon didn't report it.
    pub fn status_of(&self, component: &str) -> &str {
        self.by_name
            .get(component)
            .map(String::as_str)
            .unwrap_or("unknown")
    }
}

/// Fetch Beacon's component statuses. On ANY failure returns the default (empty, not reached)
/// snapshot — never errors.
pub async fn fetch(beacon_url: &str) -> Statuses {
    let url = format!("{}/api/status", beacon_url.trim_end_matches('/'));
    match http::fetch_text(&url, FETCH_TIMEOUT).await {
        Some(body) => parse_statuses(&body),
        None => Statuses::default(),
    }
}

/// Parse Beacon's `/api/status` JSON body into a [`Statuses`] snapshot. Invalid/foreign JSON
/// yields the default (not-reached) snapshot so the caller renders "unknown"/"—".
pub fn parse_statuses(body: &str) -> Statuses {
    match serde_json::from_str::<BeaconStatus>(body) {
        Ok(snap) => {
            let total = snap.components.len();
            let up = snap
                .components
                .iter()
                .filter(|c| c.status == "operational")
                .count();
            let components: Vec<Component> = snap
                .components
                .iter()
                .map(|c| Component {
                    name: c.name.clone(),
                    status: c.status.clone(),
                    uptime_24h: c.uptime_24h,
                })
                .collect();
            let by_name = snap
                .components
                .into_iter()
                .map(|c| (c.name, c.status))
                .collect();
            Statuses {
                by_name,
                components,
                up,
                total,
                reached: true,
            }
        }
        Err(_) => Statuses::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_statuses_maps_name_to_status_and_counts() {
        let body = r#"{
            "overall":"degraded",
            "updated_at":123,
            "components":[
                {"name":"Identity","kind":"tcp","status":"operational","uptime_24h":100.0},
                {"name":"Gateway","kind":"http","status":"degraded","uptime_24h":98.0},
                {"name":"CA","kind":"http","status":"operational","uptime_24h":100.0}
            ],
            "incidents":[]
        }"#;
        let s = parse_statuses(body);
        assert!(s.reached);
        assert_eq!(s.status_of("Identity"), "operational");
        assert_eq!(s.status_of("Gateway"), "degraded");
        assert_eq!(s.status_of("Nope"), "unknown");
        assert_eq!(s.total, 3);
        assert_eq!(s.up, 2);

        // Ordered rows (with uptime) back the operator HEALTH table.
        assert_eq!(s.components.len(), 3);
        assert_eq!(s.components[0].name, "Identity");
        assert_eq!(s.components[0].status, "operational");
        assert_eq!(s.components[0].uptime_24h, Some(100.0));
        assert_eq!(s.components[1].name, "Gateway");
        assert_eq!(s.components[1].uptime_24h, Some(98.0));
    }

    #[test]
    fn parse_statuses_on_garbage_is_default_not_error() {
        let s = parse_statuses("not json at all");
        assert!(!s.reached);
        assert_eq!(s.total, 0);
        assert_eq!(s.up, 0);
        assert_eq!(s.status_of("Anything"), "unknown");
        assert!(parse_statuses("").by_name.is_empty());
    }
}
