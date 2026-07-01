//! End-to-end Portal contract test against dev state (NO database, NO disk).
//!
//! Drives the real Router in-process via `tower::oneshot`. Tiny in-process "fake backends"
//! (one-shot `tokio::net::TcpListener`s that answer canned HTTP/1.1 JSON, routed by path)
//! stand in for the real Beacon `/api/status`, Vitals `/api/metrics`, and Watchtower
//! `/api/verify` + `/api/events`, so the live data wiring AND the resilient-when-down path
//! are both exercised with no external services.

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

/// State whose backend URLs point at the given fakes (dev catalog otherwise).
fn state_with(beacon: &str, vitals: &str, watchtower: &str) -> AppState {
    let mut config = Config::dev();
    config.beacon_url = beacon.to_string();
    config.vitals_url = vitals.to_string();
    config.watchtower_url = watchtower.to_string();
    let mut state = build_dev_state();
    state.config = Arc::new(config);
    state
}

/// Spawn a fake JSON service that answers every connection by matching the request path
/// against `routes` (first prefix match wins) and writing that body in a 200 response.
/// Unmatched paths get `{}`. Returns its `http://127.0.0.1:PORT` base URL.
async fn fake_service(routes: &'static [(&'static str, &'static str)]) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                let body = routes
                    .iter()
                    .find(|(p, _)| path.starts_with(p))
                    .map(|(_, b)| *b)
                    .unwrap_or("{}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    format!("http://{addr}")
}

// --- tests -----------------------------------------------------------------------------

#[tokio::test]
async fn healthz_ok() {
    let state = state_with("http://127.0.0.1:1", "http://127.0.0.1:1", "http://127.0.0.1:1");
    let (status, body) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn dashboard_renders_full_command_center() {
    // Beacon: Identity operational, Gateway degraded -> 1 of 2 systems operational.
    let beacon = fake_service(&[(
        "/api/status",
        r#"{"overall":"degraded","updated_at":1,"components":[
            {"name":"Identity","kind":"tcp","status":"operational","uptime_24h":100.0},
            {"name":"Gateway","kind":"http","status":"degraded","uptime_24h":97.0}
        ],"incidents":[]}"#,
    )])
    .await;
    // Vitals: latest cpu 42%, mem 63%, load1 0.75.
    let vitals = fake_service(&[(
        "/api/metrics",
        r#"{"samples":[
            {"host":"h","metric":"cpu_pct","value":42.0,"ts":200},
            {"host":"h","metric":"mem_pct","value":63.0,"ts":200},
            {"host":"h","metric":"load1","value":0.75,"ts":200}
        ]}"#,
    )])
    .await;
    // Watchtower: a verified 3-event chain + one recent login event.
    let watchtower = fake_service(&[
        ("/api/verify", r#"{"ok":true,"count":3,"head_hash":"abc"}"#),
        (
            "/api/events",
            r#"[{"seq":3,"ts":1700000000000,"actor":"alice@holdfast.local","action":"login","target":"keystone","severity":"info","detail":"d","source":"gw","prev_hash":"p","hash":"h"}]"#,
        ),
    ])
    .await;

    let state = state_with(&beacon, &vitals, &watchtower);
    let (status, html) = call(&state, get_as("/", "alice@holdfast.local")).await;
    assert_eq!(status, StatusCode::OK);

    // Greeting uses the email local-part (capitalized), rendered inside the gradient name span;
    // the full email shows in the app-bar.
    assert!(html.contains(r#"class="grad">Alice"#), "greeting names the signed-in user");
    assert!(html.contains("alice@holdfast.local"), "signed-in email rendered");

    // Live metric cards.
    assert!(html.contains("Systems online"), "systems-online card present");
    assert!(
        html.contains(r#"1<span class="metric__unit">/2</span>"#),
        "systems-online shows 1/2"
    );
    assert!(html.contains("42%"), "host CPU gauge");
    assert!(html.contains("63%"), "host memory gauge");
    assert!(html.contains("0.75"), "load average");
    assert!(html.contains("Audit events"), "audit card present");
    assert!(html.contains("Chain verified"), "audit chain shows verified");

    // Services grid: representative public app tiles + their public subdomains (mgmt surfaces
    // like Vitals/Audit are intentionally NOT on the public apex).
    for (name, url) in [
        ("Identity", "https://sso.w33d.xyz"),
        ("Status", "https://status.w33d.xyz"),
        ("Mail", "https://mail.w33d.xyz"),
        ("Blog", "https://blog.w33d.xyz"),
        ("Forum", "https://forum.w33d.xyz"),
        ("Wiki", "https://wiki.w33d.xyz"),
        ("Paste", "https://paste.w33d.xyz"),
        ("Chat", "https://chat.w33d.xyz"),
        ("Search", "https://search.w33d.xyz"),
        ("Git", "https://git.w33d.xyz"),
    ] {
        assert!(html.contains(name), "{name} tile rendered");
        assert!(html.contains(url), "{name} links to {url}");
    }
    // De-published mgmt surfaces must NOT appear on the public apex.
    assert!(!html.contains("https://vault.w33d.xyz"), "Vault is VPN-only, not a public tile");
    assert!(!html.contains("https://audit.w33d.xyz"), "Audit is VPN-only, not a public tile");

    // Live status is carried in each tile's title/aria-label (icon-dot design, not a text pill):
    // Identity -> Operational, Status(=Gateway) -> Degraded, unmapped components -> Unknown.
    assert!(html.contains(r#"title="Operational""#), "Identity shows Operational status");
    assert!(html.contains(r#"title="Degraded""#), "Status(Gateway) shows Degraded status");
    assert!(html.contains(r#"title="Unknown""#), "unmapped components show Unknown");
    // Mail is LIVE now — no Coming-soon tile should remain.
    assert!(!html.contains(">Soon<"), "no coming-soon tiles in the default catalog");

    // Recent-activity feed from Watchtower.
    assert!(html.contains("login"), "activity feed shows the action");
    assert!(
        html.contains(r#"class="feed__item""#),
        "activity feed rendered an item"
    );

    // Logout points at the gateway on the issuer host (absolute, cross-subdomain).
    assert!(
        html.contains("https://sso.w33d.xyz/_gw/auth/logout"),
        "logout points at the gateway"
    );
}

#[tokio::test]
async fn dashboard_is_resilient_when_all_backends_down() {
    // Point every backend at a closed port: each fetch fails fast and the page still renders.
    let state = state_with("http://127.0.0.1:1", "http://127.0.0.1:1", "http://127.0.0.1:1");

    let (status, html) = call(&state, get_as("/", "bob@holdfast.local")).await;
    assert_eq!(status, StatusCode::OK, "page renders even when every backend is down");
    assert!(html.contains("bob@holdfast.local"), "email still rendered");

    // Unknown status (in tile title) + "—" placeholders everywhere; no error, no panic.
    assert!(html.contains(r#"title="Unknown""#), "down Beacon -> Unknown status");
    assert!(html.contains("—"), "missing metrics render the em-dash placeholder");
    assert!(html.contains("awaiting Beacon"), "systems card degrades gracefully");
    assert!(html.contains("awaiting Vitals"), "gauges degrade gracefully");
    assert!(html.contains("awaiting Watchtower"), "audit card degrades gracefully");
    assert!(html.contains("No recent activity"), "empty activity feed placeholder");
    // App tiles still render regardless of backend health (status just degrades to Unknown).
    assert!(html.contains("https://mail.w33d.xyz"), "app grid renders even when backends are down");
}

#[tokio::test]
async fn dashboard_without_gateway_identity_falls_back() {
    // No X-Auth-Email (e.g. a direct dev hit) — the page renders with a generic label,
    // never erroring on the missing identity.
    let state = state_with("http://127.0.0.1:1", "http://127.0.0.1:1", "http://127.0.0.1:1");
    let (status, html) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("operator"), "falls back to a generic signed-in label");
    assert!(html.contains(r#"class="grad">Operator"#), "greeting falls back gracefully");
}
