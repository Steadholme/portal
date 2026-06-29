//! Dependency-light outbound HTTP/1.1 GET — the shared backbone of every backend client.
//!
//! Portal aggregates live data from several internal services (Beacon, Vitals, Watchtower).
//! Each fetch is a tiny `GET` over the `holdfast` Docker network, so rather than pull in a
//! full HTTP client we keep the same dependency-light approach the rest of the stack made: a
//! raw `tokio::net::TcpStream` for the connect, optionally wrapped in `tokio-rustls` (ring
//! backend, Mozilla roots) for an `https://` override — no OpenSSL, no heavyweight client.
//!
//! RESILIENCE IS THE CONTRACT: every failure (DNS, connect, TLS, timeout, malformed
//! response) collapses to `None`. Callers turn `None` into an "unknown"/"—" placeholder, so
//! a down or slow backend NEVER errors or hangs the dashboard.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Hard cap on the buffered response body. The JSON snapshots are small (status, a handful
/// of metric samples, at most a few hundred audit events); this only stops a misbehaving
/// upstream from exhausting memory.
const MAX_BODY: usize = 1_048_576; // 1 MiB

/// `GET url`, returning the response BODY as a string, or `None` on ANY failure. `timeout`
/// bounds the whole connect + write + read so a stalled backend can never tie up a page load.
pub async fn fetch_text(url: &str, timeout: Duration) -> Option<String> {
    match tokio::time::timeout(timeout, fetch_body(url)).await {
        Ok(Ok(body)) => Some(body),
        Ok(Err(e)) => {
            tracing::warn!(url = %url, error = %e, "backend fetch failed — rendering placeholder");
            None
        }
        Err(_) => {
            tracing::warn!(url = %url, "backend fetch timed out — rendering placeholder");
            None
        }
    }
}

/// Connect, send a minimal HTTP/1.1 GET, and return the response BODY (everything after the
/// header terminator). `Connection: close` lets us read to EOF without parsing the length.
async fn fetch_body(url: &str) -> std::io::Result<String> {
    let (tls, host, port, path) = parse_http_url(url).ok_or_else(|| io_err("invalid URL"))?;
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

    let mut acc: Vec<u8> = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&buf[..n]);
        if acc.len() > MAX_BODY {
            break;
        }
    }
    Ok(acc)
}

/// Split a raw HTTP response into its body (the bytes after the first blank line), returned
/// as a lossy UTF-8 string for JSON parsing.
fn split_body(raw: &[u8]) -> std::io::Result<String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io_err("no HTTP header terminator"))?;
    Ok(String::from_utf8_lossy(&raw[sep + 4..]).into_owned())
}

/// Parse `http(s)://host[:port]/path` into `(tls, host, port, path)`. Minimal by design — the
/// backend URLs are operator-controlled service URLs, not arbitrary user input.
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
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
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
    fn split_body_extracts_payload_after_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        assert_eq!(split_body(raw).unwrap(), "{\"ok\":true}");
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
        assert_eq!(
            parse_http_url("http://vitals:8300"),
            Some((false, "vitals".to_string(), 8300, "/".to_string()))
        );
        assert_eq!(parse_http_url("ftp://nope"), None);
    }
}
