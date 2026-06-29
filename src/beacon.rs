//! Live status: fetch Beacon's internal status JSON and map it to component statuses.
//!
//! The dashboard maps each catalog entry's `component` name to a status pill. The status
//! comes from Beacon's machine-readable snapshot at `<BEACON_URL>/api/status` (the same
//! JSON Beacon's public status page is built from). The fetch is deliberately
//! dependency-light — a raw `tokio::net::TcpStream` for the connect, wrapped in
//! `tokio-rustls` (ring backend, Mozilla roots) for an `https://` override — matching the
//! keystone/keyward/beacon portability choice (rustls + ring, no openssl).
//!
//! RESILIENCE IS THE CONTRACT: every failure (DNS, connect, timeout, non-200, bad JSON)
//! collapses to an EMPTY map. Missing components render an "unknown" pill, so a down or
//! slow Beacon NEVER errors the dashboard. Results are cached for a few seconds via
//! [`StatusCache`] so a page load never waits on more than one in-flight Beacon fetch.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Per-fetch budget (connect + write + read). Beacon is in-network; keep it short so a
/// stalled connection can never tie a page load up for long.
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a fetched snapshot stays fresh before the next page load refetches.
pub const CACHE_TTL: Duration = Duration::from_secs(5);

/// Just the slice of Beacon's `/api/status` JSON we need: each component's name + status.
/// Extra fields (uptime, latency, incidents, overall) are ignored.
#[derive(Debug, Deserialize)]
struct BeaconStatus {
    #[serde(default)]
    components: Vec<BeaconComponent>,
}

#[derive(Debug, Deserialize)]
struct BeaconComponent {
    name: String,
    status: String,
}

/// A few-second cache around [`fetch_statuses`]. Cheap to clone (state behind `Arc`).
#[derive(Clone)]
pub struct StatusCache {
    ttl: Duration,
    inner: Arc<Mutex<Option<(Instant, HashMap<String, String>)>>>,
}

impl StatusCache {
    /// New cache with the given freshness window.
    pub fn new(ttl: Duration) -> Self {
        StatusCache {
            ttl,
            inner: Arc::new(Mutex::new(None)),
        }
    }

    /// Return component-name -> status, serving a cached snapshot while it is fresh and
    /// otherwise refetching from `<beacon_url>/api/status`. The lock is never held across
    /// the network `.await`, so concurrent page loads stay non-blocking.
    pub async fn statuses(&self, beacon_url: &str) -> HashMap<String, String> {
        if let Some((at, map)) = self.inner.lock().unwrap().as_ref() {
            if at.elapsed() < self.ttl {
                return map.clone();
            }
        }
        let fresh = fetch_statuses(beacon_url).await;
        *self.inner.lock().unwrap() = Some((Instant::now(), fresh.clone()));
        fresh
    }
}

/// Fetch Beacon's component statuses as a name -> status map. On ANY failure returns an
/// EMPTY map (never errors) so the dashboard renders "unknown" pills instead of failing.
pub async fn fetch_statuses(beacon_url: &str) -> HashMap<String, String> {
    let url = format!("{}/api/status", beacon_url.trim_end_matches('/'));
    match tokio::time::timeout(FETCH_TIMEOUT, fetch_body(&url)).await {
        Ok(Ok(body)) => parse_statuses(&body),
        Ok(Err(e)) => {
            tracing::warn!(url = %url, error = %e, "beacon status fetch failed — rendering unknown");
            HashMap::new()
        }
        Err(_) => {
            tracing::warn!(url = %url, "beacon status fetch timed out — rendering unknown");
            HashMap::new()
        }
    }
}

/// Parse Beacon's `/api/status` JSON body into a name -> status map. Invalid/foreign JSON
/// yields an empty map (caller renders "unknown").
pub fn parse_statuses(body: &str) -> HashMap<String, String> {
    match serde_json::from_str::<BeaconStatus>(body) {
        Ok(snap) => snap
            .components
            .into_iter()
            .map(|c| (c.name, c.status))
            .collect(),
        Err(_) => HashMap::new(),
    }
}

/// Connect, send a minimal HTTP/1.1 GET, and return the response BODY (everything after the
/// header terminator). `Connection: close` lets us read to EOF without parsing the length.
async fn fetch_body(url: &str) -> std::io::Result<String> {
    let (tls, host, port, path) =
        parse_http_url(url).ok_or_else(|| io_err("invalid BEACON_URL"))?;
    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    let raw = if tls {
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|_| io_err("invalid TLS server name"))?;
        let stream = tls_connector().connect(server_name, tcp).await?;
        send_recv(stream, &host, &path).await?
    } else {
        send_recv(tcp, &host, &path).await?
    };
    split_body(&raw)
}

/// Write a minimal HTTP/1.1 GET over `stream` and read the whole response to EOF.
async fn send_recv<S>(mut stream: S, host: &str, path: &str) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: portal/0.1\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut acc: Vec<u8> = Vec::with_capacity(2048);
    let mut buf = [0u8; 2048];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&buf[..n]);
        // Hard cap so a misbehaving upstream can't exhaust memory; the status snapshot is tiny.
        if acc.len() > 262_144 {
            break;
        }
    }
    Ok(acc)
}

/// Split a raw HTTP response into its body (the bytes after the first blank line),
/// returned as a lossy UTF-8 string for JSON parsing.
fn split_body(raw: &[u8]) -> std::io::Result<String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io_err("no HTTP header terminator"))?;
    Ok(String::from_utf8_lossy(&raw[sep + 4..]).into_owned())
}

/// Parse `http(s)://host[:port]/path` into `(tls, host, port, path)`. Minimal by design —
/// `BEACON_URL` is an operator-controlled service URL, not arbitrary user input.
fn parse_http_url(url: &str) -> Option<(bool, String, u16, String)> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return None;
    };

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return None;
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()?),
        None => (authority.to_string(), if tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        return None;
    }
    let path = if path.is_empty() { "/".to_string() } else { path.to_string() };
    Some((tls, host, port, path))
}

/// Process-wide rustls client connector (ring provider + Mozilla roots), built once.
fn tls_connector() -> TlsConnector {
    static CONNECTOR: OnceLock<TlsConnector> = OnceLock::new();
    CONNECTOR
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("ring provider supports the default protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            TlsConnector::from(Arc::new(config))
        })
        .clone()
}

fn io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_statuses_maps_name_to_status() {
        let body = r#"{
            "overall":"degraded",
            "updated_at":123,
            "components":[
                {"name":"Identity","kind":"tcp","status":"operational","uptime_24h":100.0},
                {"name":"Gateway","kind":"http","status":"degraded","uptime_24h":98.0}
            ],
            "incidents":[]
        }"#;
        let map = parse_statuses(body);
        assert_eq!(map.get("Identity").map(String::as_str), Some("operational"));
        assert_eq!(map.get("Gateway").map(String::as_str), Some("degraded"));
        assert_eq!(map.get("Nope"), None);
    }

    #[test]
    fn parse_statuses_on_garbage_is_empty_not_error() {
        assert!(parse_statuses("not json at all").is_empty());
        assert!(parse_statuses("").is_empty());
    }

    #[test]
    fn split_body_extracts_payload_after_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"components\":[]}";
        assert_eq!(split_body(raw).unwrap(), "{\"components\":[]}");
    }

    #[test]
    fn parse_http_url_variants() {
        assert_eq!(
            parse_http_url("http://beacon:8400/api/status"),
            Some((false, "beacon".to_string(), 8400, "/api/status".to_string()))
        );
        assert_eq!(
            parse_http_url("https://status.w33d.xyz/api/status"),
            Some((true, "status.w33d.xyz".to_string(), 443, "/api/status".to_string()))
        );
        assert_eq!(parse_http_url("ftp://nope"), None);
    }
}
