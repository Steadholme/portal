//! End-to-end Portal contract test against dev state (NO database, NO disk).
//!
//! Drives the real Router in-process via `tower::oneshot`. A tiny in-process "fake Beacon"
//! (a one-shot `tokio::net::TcpListener` that writes a canned HTTP/1.1 response) stands in
//! for the real Beacon `/api/status`, so the live-status mapping and the
//! resilient-when-down path are both exercised with no external services.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use portal::config::Config;
use portal::{app, build_dev_state, AppState};
use tower::ServiceExt;

// --- HTTP helpers ----------------------------------------------------------------------

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn get_as(uri: &str, email: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("X-Auth-Email", email)
        .body(Body::empty())
        .unwrap()
}

/// State whose Beacon URL points at `beacon_url` (dev catalog otherwise).
fn state_with_beacon(beacon_url: &str) -> AppState {
    let mut config = Config::dev();
    config.beacon_url = beacon_url.to_string();
    let mut state = build_dev_state();
    state.config = Arc::new(config);
    state
}

/// Spawn a one-shot fake Beacon that answers exactly one connection with `json` as the body
/// of a 200 response, then returns its `http://127.0.0.1:PORT` base URL.
async fn fake_beacon(json: &'static str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            // Drain the request (we don't route on it) up to the first read.
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                json.len(),
                json
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
        }
    });
    format!("http://{addr}")
}

// --- tests -----------------------------------------------------------------------------

#[tokio::test]
async fn healthz_ok() {
    let state = build_dev_state();
    let (status, body) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn dashboard_renders_tiles_with_email_and_live_pills() {
    // Fake Beacon reports Identity operational, Gateway degraded.
    let beacon = fake_beacon(
        r#"{"overall":"degraded","updated_at":1,"components":[
            {"name":"Identity","kind":"tcp","status":"operational","uptime_24h":100.0},
            {"name":"Gateway","kind":"http","status":"degraded","uptime_24h":97.0}
        ],"incidents":[]}"#,
    )
    .await;
    let state = state_with_beacon(&beacon);

    let (status, html) = call(&state, get_as("/", "alice@holdfast.local")).await;
    assert_eq!(status, StatusCode::OK);

    // Heading + the signed-in email from X-Auth-Email.
    assert!(html.contains("HOLDFAST · Sovereign Cloud"), "brand heading present");
    assert!(html.contains("alice@holdfast.local"), "signed-in email rendered");

    // Tiles for the default catalog services + links to their public subdomains.
    for (name, url) in [
        ("Identity", "https://id.w33d.xyz"),
        ("Status", "https://status.w33d.xyz"),
        ("Vitals", "https://vitals.w33d.xyz"),
        ("Audit", "https://audit.w33d.xyz"),
        ("Mail", "https://mail.w33d.xyz"),
    ] {
        assert!(html.contains(name), "{name} tile rendered");
        assert!(html.contains(url), "{name} links to {url}");
    }

    // Live pills mapped from Beacon: Identity -> Operational, Status(=Gateway) -> Degraded.
    assert!(html.contains(">Operational<"), "Identity shows Operational pill");
    assert!(html.contains(">Degraded<"), "Status(Gateway) shows Degraded pill");
    // Mail is coming soon (no live pill).
    assert!(html.contains(">Coming soon<"), "Mail shows Coming soon tag");
    // Components Beacon doesn't report (Vitals/Audit) fall back to Unknown.
    assert!(html.contains(">Unknown<"), "unmapped components show Unknown");

    // Logout points at the gateway on the issuer host (absolute, cross-subdomain).
    assert!(
        html.contains("https://id.w33d.xyz/_gw/auth/logout"),
        "logout points at the gateway"
    );
}

#[tokio::test]
async fn dashboard_is_resilient_when_beacon_is_down() {
    // Point at a closed port: the fetch fails fast and every live tile renders Unknown.
    let state = state_with_beacon("http://127.0.0.1:1");

    let (status, html) = call(&state, get_as("/", "bob@holdfast.local")).await;
    assert_eq!(status, StatusCode::OK, "page renders even when Beacon is down");
    assert!(html.contains("bob@holdfast.local"), "email still rendered");
    assert!(html.contains(">Unknown<"), "down Beacon -> Unknown pills");
    // The four live tiles all degrade to Unknown; only Mail keeps its Coming soon tag.
    assert!(html.contains(">Coming soon<"), "coming-soon tile unaffected");
}

#[tokio::test]
async fn dashboard_without_gateway_identity_falls_back() {
    // No X-Auth-Email (e.g. a direct dev hit) — the page renders with a generic label,
    // never erroring on the missing identity.
    let state = state_with_beacon("http://127.0.0.1:1");
    let (status, html) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("operator"), "falls back to a generic signed-in label");
}
