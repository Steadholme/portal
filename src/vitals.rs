//! Vitals client: the latest host gauges (CPU %, memory %, load) for the metric cards.
//!
//! Vitals exposes a JSON time-series at `<VITALS_URL>/api/metrics?metric=&since=`. We ask for
//! a short recent window and keep, per metric, the freshest sample (max `ts`). A single
//! request returns every metric for the window; we extract the three the dashboard headlines.
//!
//! RESILIENCE IS THE CONTRACT: any failure (down, timeout, bad JSON) leaves every gauge at
//! `None`, which the dashboard renders as "—".

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::http;

/// Per-fetch budget. Vitals is in-network; keep it short.
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);
/// How far back to ask for samples. Wide enough to always contain a recent scrape, narrow
/// enough to keep the payload tiny regardless of the metric vocabulary's size.
const WINDOW_SECS: i64 = 1_800;

/// Metric names (Vitals' stable string vocabulary).
const M_CPU_PCT: &str = "cpu_pct";
const M_MEM_PCT: &str = "mem_pct";
const M_LOAD1: &str = "load1";

/// `/api/metrics` response envelope: `{ "samples": [ { metric, value, ts, host? }, ... ] }`.
#[derive(Debug, Deserialize)]
struct MetricsResponse {
    #[serde(default)]
    samples: Vec<Sample>,
}

#[derive(Debug, Deserialize)]
struct Sample {
    metric: String,
    value: f64,
    ts: i64,
}

/// The headline host gauges. `None` means "no recent sample" / Vitals unreachable -> "—".
#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics {
    pub cpu_pct: Option<f64>,
    pub mem_pct: Option<f64>,
    pub load1: Option<f64>,
}

/// Fetch the latest host gauges. On ANY failure returns the default (all `None`) — never errors.
pub async fn fetch(vitals_url: &str) -> Metrics {
    let since = now_secs() - WINDOW_SECS;
    let url = format!(
        "{}/api/metrics?since={}",
        vitals_url.trim_end_matches('/'),
        since
    );
    match http::fetch_text(&url, FETCH_TIMEOUT).await {
        Some(body) => parse_metrics(&body),
        None => Metrics::default(),
    }
}

/// Parse a `/api/metrics` body and keep, per headline metric, the freshest sample's value.
/// Foreign/invalid JSON yields all-`None`.
pub fn parse_metrics(body: &str) -> Metrics {
    let resp: MetricsResponse = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return Metrics::default(),
    };
    // Track the freshest (max ts) value seen for each metric of interest.
    let mut latest: [(i64, f64); 3] = [(i64::MIN, 0.0); 3];
    for s in &resp.samples {
        let idx = match s.metric.as_str() {
            M_CPU_PCT => 0,
            M_MEM_PCT => 1,
            M_LOAD1 => 2,
            _ => continue,
        };
        if s.ts >= latest[idx].0 {
            latest[idx] = (s.ts, s.value);
        }
    }
    let pick = |i: usize| (latest[i].0 != i64::MIN).then_some(latest[i].1);
    Metrics {
        cpu_pct: pick(0),
        mem_pct: pick(1),
        load1: pick(2),
    }
}

/// Current epoch seconds (saturating; the clock is always well past the epoch in practice).
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_metrics_keeps_freshest_per_metric() {
        let body = r#"{"samples":[
            {"host":"h1","metric":"cpu_pct","value":11.0,"ts":100},
            {"host":"h1","metric":"cpu_pct","value":42.5,"ts":200},
            {"host":"h1","metric":"mem_pct","value":63.0,"ts":150},
            {"host":"h1","metric":"load1","value":0.75,"ts":180},
            {"host":"h1","metric":"disk_pct","value":80.0,"ts":190}
        ]}"#;
        let m = parse_metrics(body);
        assert_eq!(m.cpu_pct, Some(42.5));
        assert_eq!(m.mem_pct, Some(63.0));
        assert_eq!(m.load1, Some(0.75));
    }

    #[test]
    fn parse_metrics_missing_metric_is_none() {
        let body = r#"{"samples":[{"host":"h","metric":"cpu_pct","value":5.0,"ts":1}]}"#;
        let m = parse_metrics(body);
        assert_eq!(m.cpu_pct, Some(5.0));
        assert_eq!(m.mem_pct, None);
        assert_eq!(m.load1, None);
    }

    #[test]
    fn parse_metrics_on_garbage_is_default() {
        let m = parse_metrics("nope");
        assert!(m.cpu_pct.is_none() && m.mem_pct.is_none() && m.load1.is_none());
        let empty = parse_metrics(r#"{"samples":[]}"#);
        assert!(empty.cpu_pct.is_none());
    }
}
