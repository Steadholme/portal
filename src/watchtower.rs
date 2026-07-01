//! Watchtower client: the audit-chain count + integrity, and the recent-activity feed.
//!
//! Two internal endpoints back the dashboard:
//! - `GET <WATCHTOWER_URL>/api/verify` -> `{ ok, count, head_hash, first_broken_seq? }` — the
//!   chain length and whether it currently verifies (the "Audit events" card + verified dot).
//! - `GET <WATCHTOWER_URL>/api/events`  -> a newest-first list of sealed audit events — the
//!   "Recent activity" feed (we keep the most recent few).
//!
//! RESILIENCE IS THE CONTRACT: any failure leaves the count at `None` (rendered "—") and the
//! feed empty — never an error.

use std::time::Duration;

use serde::Deserialize;

use crate::http;

/// Per-fetch budget. Watchtower is in-network; keep it short.
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);
/// How many recent events the dashboard activity feed shows.
pub const FEED_LEN: usize = 8;
/// How many recent events the operator console's cross-service AUDIT viewer loads (the
/// client then filters + progressively reveals them). Bounded so the payload stays small.
pub const AUDIT_MAX: usize = 200;

/// `/api/verify` response we care about: the chain length, integrity flag + head hash.
#[derive(Debug, Default, Deserialize)]
pub struct Verify {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub count: usize,
    /// The chain head hash (shown in the operator console's audit header).
    #[serde(default)]
    pub head_hash: String,
    /// Whether Watchtower answered at all (drives "—" vs a real count + the verified dot).
    #[serde(skip)]
    pub reached: bool,
}

/// One sealed audit event (the fields the activity feed + audit viewer render; chain hashes are
/// ignored). `ts` is epoch MILLISECONDS (Watchtower stamps appends with `now_ms`).
#[derive(Clone, Debug, Deserialize)]
pub struct Event {
    #[serde(default)]
    pub ts: i64,
    /// Emitting service (the audit viewer filters by it). Absent on older events -> "".
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub actor: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub severity: String,
}

/// Fetch the chain integrity summary. On ANY failure returns the default (not reached).
pub async fn fetch_verify(watchtower_url: &str) -> Verify {
    let url = format!("{}/api/verify", watchtower_url.trim_end_matches('/'));
    match http::fetch_text(&url, FETCH_TIMEOUT).await {
        Some(body) => parse_verify(&body),
        None => Verify::default(),
    }
}

/// Fetch the recent-activity feed (already newest-first), truncated to [`FEED_LEN`]. On ANY
/// failure returns an empty feed.
pub async fn fetch_events(watchtower_url: &str) -> Vec<Event> {
    let url = format!("{}/api/events", watchtower_url.trim_end_matches('/'));
    match http::fetch_text(&url, FETCH_TIMEOUT).await {
        Some(body) => parse_events(&body),
        None => Vec::new(),
    }
}

/// Fetch the cross-service audit stream for the operator console (newest-first), truncated to
/// [`AUDIT_MAX`]. On ANY failure returns an empty list — the console degrades, never errors.
pub async fn fetch_audit(watchtower_url: &str) -> Vec<Event> {
    let url = format!("{}/api/events", watchtower_url.trim_end_matches('/'));
    match http::fetch_text(&url, FETCH_TIMEOUT).await {
        Some(body) => parse_events_capped(&body, AUDIT_MAX),
        None => Vec::new(),
    }
}

/// Parse `/api/verify`. Foreign/invalid JSON yields the default (not reached).
pub fn parse_verify(body: &str) -> Verify {
    match serde_json::from_str::<Verify>(body) {
        Ok(mut v) => {
            v.reached = true;
            v
        }
        Err(_) => Verify::default(),
    }
}

/// Parse `/api/events` (a newest-first JSON array), keeping the most recent [`FEED_LEN`].
/// Foreign/invalid JSON yields an empty feed.
pub fn parse_events(body: &str) -> Vec<Event> {
    parse_events_capped(body, FEED_LEN)
}

/// Parse `/api/events` (a newest-first JSON array), keeping the most recent `cap` events.
/// Foreign/invalid JSON yields an empty list.
pub fn parse_events_capped(body: &str, cap: usize) -> Vec<Event> {
    match serde_json::from_str::<Vec<Event>>(body) {
        Ok(mut events) => {
            events.truncate(cap);
            events
        }
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_verify_reads_count_and_ok() {
        let v = parse_verify(r#"{"ok":true,"count":42,"head_hash":"abc"}"#);
        assert!(v.reached);
        assert!(v.ok);
        assert_eq!(v.count, 42);
        assert_eq!(v.head_hash, "abc");

        let broken = parse_verify(r#"{"ok":false,"count":9,"head_hash":"x","first_broken_seq":3}"#);
        assert!(broken.reached);
        assert!(!broken.ok);
        assert_eq!(broken.count, 9);
    }

    #[test]
    fn parse_verify_on_garbage_is_not_reached() {
        let v = parse_verify("nope");
        assert!(!v.reached);
        assert_eq!(v.count, 0);
        assert!(!v.ok);
    }

    #[test]
    fn parse_events_truncates_to_feed_len_newest_first() {
        let mut items = String::from("[");
        for i in 0..20 {
            if i > 0 {
                items.push(',');
            }
            items.push_str(&format!(
                r#"{{"seq":{i},"ts":{ts},"actor":"u{i}","action":"login","target":"keystone","severity":"info","detail":"d","source":"s","prev_hash":"p","hash":"h"}}"#,
                ts = 1_700_000_000_000i64 + i
            ));
        }
        items.push(']');
        let events = parse_events(&items);
        assert_eq!(events.len(), FEED_LEN);
        // Newest-first ordering is preserved (first element is the array's first element).
        assert_eq!(events[0].actor, "u0");
        assert_eq!(events[0].action, "login");
    }

    #[test]
    fn parse_events_reads_source_for_audit_viewer() {
        let events = parse_events(
            r#"[{"seq":1,"ts":1700000000000,"source":"keystone","actor":"alice","action":"login","target":"sso","severity":"info"}]"#,
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, "keystone");
        assert_eq!(events[0].actor, "alice");
    }

    #[test]
    fn parse_events_capped_keeps_more_than_feed_len() {
        let mut items = String::from("[");
        for i in 0..(AUDIT_MAX + 50) {
            if i > 0 {
                items.push(',');
            }
            items.push_str(&format!(
                r#"{{"seq":{i},"ts":{ts},"source":"s{i}","actor":"u{i}","action":"a","target":"t","severity":"info"}}"#,
                ts = 1_700_000_000_000i64 + i as i64
            ));
        }
        items.push(']');
        let events = parse_events_capped(&items, AUDIT_MAX);
        assert_eq!(events.len(), AUDIT_MAX, "capped at AUDIT_MAX");
        assert_eq!(events[0].source, "s0", "newest-first order preserved");
    }

    #[test]
    fn parse_events_on_garbage_is_empty() {
        assert!(parse_events("nope").is_empty());
        assert!(parse_events("{}").is_empty());
        assert!(parse_events("[]").is_empty());
    }
}
