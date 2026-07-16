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
use hmac::{Hmac, Mac};
use portal::auth::{GatewayZoneVerifier, HEADER_GATEWAY_ZONE, HEADER_GATEWAY_ZONE_SIG};
use portal::config::Config;
use portal::manifest::{parse_projection, ProjectionAudience};
use portal::{app, build_dev_state, AppState};
use sha2::Sha256;
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

fn get_as_zone(uri: &str, email: &str, zone: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("X-Auth-Email", email)
        .header("X-Gateway-Zone", zone)
        .body(Body::empty())
        .unwrap()
}

/// Request carrying a gateway-injected identity + groups (the admin gate reads `X-Auth-Groups`).
fn get_as_groups(uri: &str, email: &str, groups: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("X-Auth-Email", email)
        .header("X-Auth-Groups", groups)
        .body(Body::empty())
        .unwrap()
}

/// State whose backend URLs point at the given fakes (dev catalog otherwise).
fn state_with(beacon: &str, vitals: &str, watchtower: &str) -> AppState {
    state_with_beacons(beacon, beacon, vitals, watchtower)
}

/// State with independently selectable public and operator Beacon projections.
fn state_with_beacons(
    public_beacon: &str,
    operator_beacon: &str,
    vitals: &str,
    watchtower: &str,
) -> AppState {
    let mut config = Config::dev();
    config.beacon_public_url = public_beacon.to_string();
    config.beacon_url = operator_beacon.to_string();
    config.vitals_url = vitals.to_string();
    config.watchtower_url = watchtower.to_string();
    let mut state = build_dev_state();
    state.config = Arc::new(config);
    state
}

fn manifest_projection(audience: &str, id: &str, name: &str, url: &str) -> String {
    let fingerprint = if audience == "public" {
        "a".repeat(64)
    } else {
        "b".repeat(64)
    };
    format!(
        r#"{{"schemaVersion":"holdfast.experience-projection.v1","release":"1.0.0","fingerprint":"sha256:{fingerprint}","audience":"{audience}","surfaces":[{{"id":"{id}","name":"{name}","description":"Manifest-owned surface","url":"{url}","category":"platform","icon":"grid","statusComponent":"Example","profile":"control","capabilities":["launch"],"comingSoon":false}}]}}"#
    )
}

fn manifest_state() -> AppState {
    let public = parse_projection(
        &manifest_projection(
            "public",
            "mail-web",
            "Manifest Mail",
            "https://mail.w33d.xyz",
        ),
        ProjectionAudience::Public,
    )
    .unwrap();
    let estate = parse_projection(
        &manifest_projection(
            "estate",
            "vault-ops",
            "Manifest Vault",
            "https://vault.w33d.xyz",
        ),
        ProjectionAudience::Estate,
    )
    .unwrap();
    let mut config = Config::dev();
    config.beacon_public_url = "http://127.0.0.1:1".to_string();
    config.beacon_url = "http://127.0.0.1:1".to_string();
    config.vitals_url = "http://127.0.0.1:1".to_string();
    config.watchtower_url = "http://127.0.0.1:1".to_string();
    config.catalog = public.catalog;
    config.internal_catalog = estate.catalog;
    config.public_projection = Some(public.identity);
    config.estate_projection = Some(estate.identity);
    config.zone_verifier = GatewayZoneVerifier::new("test-key");
    let mut state = build_dev_state();
    state.config = Arc::new(config);
    state
}

fn zone_signature(key: &str, host: &str, zone: &str, window: i64) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
    mac.update(b"holdfast.gateway-zone.v1\n");
    mac.update(b"portal-root\n");
    mac.update(host.as_bytes());
    mac.update(b"\n");
    mac.update(zone.as_bytes());
    mac.update(b"\n");
    mac.update(window.to_string().as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn current_minute() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        / 60
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

/// Dynamic-body variant used when a test needs a generated Beacon projection.
async fn fake_status_service(body: String) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = Arc::new(body);
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let body = Arc::clone(&body);
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
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
    let state = state_with(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
    );
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
            r#"[{"seq":3,"ts":1700000000000,"actor":"alice@steadholme.local","action":"login","target":"keystone","severity":"info","detail":"d","source":"gw","prev_hash":"p","hash":"h"}]"#,
        ),
    ])
    .await;

    let state = state_with(&beacon, &vitals, &watchtower);
    let (status, html) = call(&state, get_as("/", "alice@steadholme.local")).await;
    assert_eq!(status, StatusCode::OK);

    // Greeting uses the email local-part (capitalized) and exposes a stable identity hook;
    // the full email remains available in the account disclosure.
    assert!(
        html.contains(r#"data-user-name="Alice">Alice</span>"#),
        "greeting names the signed-in user"
    );
    assert!(
        html.contains("alice@steadholme.local"),
        "signed-in email rendered"
    );
    assert!(
        html.contains(r#"<main id="top">"#),
        "main landmark rendered"
    );
    assert!(
        html.contains(r##"class="skiplink" href="#catalog""##),
        "keyboard users can skip to the service catalog"
    );
    assert!(
        html.contains(
            r#"id="account-toggle" type="button" aria-expanded="false" aria-controls="account-popover""#
        ),
        "account disclosure exposes its controlled region"
    );
    assert!(
        html.contains(r#"id="account-popover" aria-label="Account" hidden"#),
        "account disclosure starts collapsed"
    );
    assert!(
        !html.contains(r#"role="menu""#) && !html.contains(r#"role="menuitem""#),
        "ordinary account links do not claim application-menu semantics"
    );
    assert!(
        html.contains(r#"id="personalization-status" role="status" aria-live="polite""#),
        "personalization changes have an independent live region"
    );

    // Live metric cards.
    assert!(
        html.contains("Systems online"),
        "systems-online card present"
    );
    assert!(
        html.contains(r#"1<span class="metric__unit">/2</span>"#),
        "systems-online shows 1/2"
    );
    assert!(html.contains("42%"), "host CPU gauge");
    assert!(html.contains("63%"), "host memory gauge");
    assert!(html.contains("0.75"), "load average");
    assert!(html.contains("Audit events"), "audit card present");
    assert!(
        html.contains("Chain verified"),
        "audit chain shows verified"
    );

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
    assert!(
        !html.contains("https://vault.w33d.xyz"),
        "Vault is VPN-only, not a public tile"
    );
    assert!(
        !html.contains("https://audit.w33d.xyz"),
        "Audit is VPN-only, not a public tile"
    );

    // Live status is silent for operational/unknown tiles; only degraded/down render a status dot.
    assert!(
        !html.contains(r#"title="Operational""#),
        "operational tiles are silent"
    );
    assert!(
        html.contains(r#"title="Degraded""#),
        "Status(Gateway) shows Degraded status"
    );
    assert!(
        !html.contains(r#"title="Unknown""#),
        "unmapped components do not render status dots"
    );
    assert_eq!(
        html.matches(r#"class="app__status"#).count(),
        1,
        "only the degraded Status tile renders a status node"
    );
    assert!(
        html.contains(r#"class="incidentbar incidentbar--warn""#),
        "degraded Beacon state renders an incident banner"
    );
    assert!(
        html.contains("Gateway"),
        "incident banner names the degraded component"
    );
    assert!(
        html.contains(r#"title="Mail — SSO webmail"#),
        "tiles expose native title tooltips"
    );
    assert!(
        html.contains(r#"id="ident" data-section"#),
        "identity keeps its own field band"
    );
    assert!(
        html.contains(r#"id="obs" data-section"#),
        "observability keeps its own field band"
    );
    // Mail is LIVE now — no Coming-soon tile should remain.
    assert!(
        !html.contains(">Soon<"),
        "no coming-soon tiles in the default catalog"
    );

    // Client-side launcher enhancements stay front-end only: stable tile ids, star controls,
    // a personal-apps mount, and an accessible command-palette shell.
    assert!(
        html.contains(r#"id="personalapps""#),
        "personal apps mount rendered"
    );
    assert!(
        html.contains(r#"id="pinnedapps""#),
        "pinned apps empty state rendered"
    );
    assert!(
        html.contains("Use the star on any service"),
        "pinned apps empty state invites pinning"
    );
    assert!(
        html.contains(r#"id="cmdpalette" role="dialog""#),
        "command palette dialog shell"
    );
    assert!(
        html.contains(r#"aria-modal="true""#),
        "command palette is modal"
    );
    assert!(
        html.contains("holdfast.portal.pinnedApps.v1"),
        "pinned apps use namespaced localStorage"
    );
    assert!(
        html.contains("holdfast.portal.recentApps.v1"),
        "recent apps use namespaced localStorage"
    );
    assert!(
        html.contains(r#"data-app-id="https://mail.w33d.xyz""#),
        "tiles expose stable app ids"
    );
    assert!(
        html.contains(r#"data-pin-button data-app-id="https://mail.w33d.xyz""#),
        "tiles include a pin control"
    );

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
async fn dashboard_estate_bridge_uses_odyssey_runtime_and_keeps_status_public() {
    let state = state_with(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
    );
    let (status, html) = call(&state, get_as("/", "alice@steadholme.local")).await;
    assert_eq!(status, StatusCode::OK);

    assert!(html.contains(r#"<html lang="en" data-ody-profile="portal">"#));
    assert!(html.contains(r#"<body class="portal-home" data-ody-shell="1.3">"#));
    assert!(html.contains(r#"<link rel="icon" href="data:image/svg+xml,"#));
    assert!(
        html.contains("odyssey-wire v1"),
        "Wire runtime is vendored inline"
    );
    assert!(
        html.contains("odyssey-spark v1"),
        "Spark runtime is vendored inline"
    );
    assert!(
        html.contains("odyssey-motion v1"),
        "reduced-motion-aware polish is enabled"
    );

    assert!(html.contains(r#"id="estate-live" role="region" aria-labelledby="estate-title""#));
    assert!(html.contains("One estate, three trust paths"));
    assert!(
        html.contains(r#"data-public-surface-count="22""#),
        "public count comes from Config catalog"
    );
    assert!(html.contains("Anonymous, read-only"));
    assert!(html.contains(
        "status.w33d.xyz</a> stays publicly readable; no Portal identity or WireGuard connection is required."
    ));
    assert!(html.contains("WireGuard required"));
    assert!(html.contains("Fleet health"));
    assert!(html.contains("Recent signals"));

    // The only Wire canary is the isolated live snapshot. JS-owned catalog, pin and palette nodes
    // are never replacement targets.
    assert_eq!(
        html.matches(r##"data-wire-target="#estate-live""##).count(),
        1
    );
    assert!(html.contains(r##"data-wire-select="#estate-live""##));
    assert!(html.contains(r#"data-wire-swap="outer""#));
    assert!(!html.contains(r##"data-wire-target="#appsections""##));
    assert!(
        !html.contains(r#"<form class="search" role="search" method="get" action="/" data-wire"#)
    );
}

#[tokio::test]
async fn manifest_projection_and_host_bound_zone_signature_never_leak_estate() {
    let state = manifest_state();

    let external = Request::builder()
        .uri("/")
        .header("Host", "w33d.xyz")
        .header("X-Auth-Email", "alice@steadholme.local")
        .body(Body::empty())
        .unwrap();
    let (status, public_html) = call(&state, external).await;
    assert_eq!(status, StatusCode::OK);
    assert!(public_html.contains("Manifest Mail"));
    assert!(public_html.contains(r#"data-product-id="mail-web""#));
    assert!(public_html.contains(r#"data-ody-profile="control""#));
    assert!(public_html.contains(r#"data-manifest-audience="public""#));
    assert!(public_html.contains(r#"data-manifest-surface-count="1""#));
    assert!(public_html.contains(&format!("sha256:{}", "a".repeat(64))));
    for secret in [
        "Manifest Vault",
        "vault.w33d.xyz",
        "vault-ops",
        &format!("sha256:{}", "b".repeat(64)),
        r#"data-manifest-audience="estate""#,
    ] {
        assert!(
            !public_html.contains(secret),
            "external response leaked {secret}"
        );
    }

    let valid_sig = zone_signature("test-key", "w33d.xyz", "internal", current_minute());
    let internal = Request::builder()
        .uri("/")
        .header("Host", "w33d.xyz")
        .header("X-Auth-Email", "alice@steadholme.local")
        .header(HEADER_GATEWAY_ZONE, "internal")
        .header(HEADER_GATEWAY_ZONE_SIG, valid_sig.clone())
        .body(Body::empty())
        .unwrap();
    let (status, internal_html) = call(&state, internal).await;
    assert_eq!(status, StatusCode::OK);
    assert!(internal_html.contains("Manifest Mail"));
    assert!(internal_html.contains("Manifest Vault"));
    assert!(internal_html.contains(r#"data-product-id="vault-ops""#));
    assert!(internal_html.contains(r#"data-manifest-surface-count="2""#));
    assert!(internal_html.contains(r#"data-manifest-audience="public""#));
    assert!(internal_html.contains(r#"data-manifest-audience="estate""#));
    assert!(internal_html.contains(&format!("sha256:{}", "a".repeat(64))));
    assert!(internal_html.contains(&format!("sha256:{}", "b".repeat(64))));

    let downgraded = [
        Request::builder()
            .uri("/")
            .header("Host", "w33d.xyz")
            .header(HEADER_GATEWAY_ZONE, "internal")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri("/")
            .header("Host", "w33d.xyz")
            .header(HEADER_GATEWAY_ZONE, "internal")
            .header(HEADER_GATEWAY_ZONE_SIG, "forged")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri("/")
            .header("Host", "evil.example")
            .header(HEADER_GATEWAY_ZONE, "internal")
            .header(HEADER_GATEWAY_ZONE_SIG, valid_sig)
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri("/")
            .header("Host", "w33d.xyz")
            .header(HEADER_GATEWAY_ZONE, "external")
            .header(HEADER_GATEWAY_ZONE_SIG, "forged")
            .header("X-Wire", "1")
            .body(Body::empty())
            .unwrap(),
    ];
    for request in downgraded {
        let (status, html) = call(&state, request).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!html.contains("Manifest Vault"));
        assert!(!html.contains("vault.w33d.xyz"));
        assert!(!html.contains(&format!("sha256:{}", "b".repeat(64))));
        assert!(html.contains(&format!("sha256:{}", "a".repeat(64))));
    }
}

#[tokio::test]
async fn beacon_scopes_keep_operator_components_out_of_external_full_and_wire() {
    let public_beacon = fake_status_service(
        serde_json::json!({
            "overall": "operational",
            "updated_at": 1,
            "components": [{
                "name": "Gateway",
                "kind": "http",
                "status": "operational",
                "uptime_24h": 100.0
            }],
            "incidents": []
        })
        .to_string(),
    )
    .await;

    let mut operator_components = vec![
        serde_json::json!({
            "name": "Gateway",
            "kind": "http",
            "status": "operational",
            "uptime_24h": 100.0
        }),
        serde_json::json!({
            "name": "CA",
            "kind": "tcp",
            "status": "down",
            "uptime_24h": 51.0
        }),
    ];
    operator_components.extend((1..=49).map(|index| {
        serde_json::json!({
            "name": format!("Internal-{index:02}"),
            "kind": "http",
            "status": "operational",
            "uptime_24h": 100.0
        })
    }));
    let operator_beacon = fake_status_service(
        serde_json::json!({
            "overall": "down",
            "updated_at": 1,
            "components": operator_components,
            "incidents": []
        })
        .to_string(),
    )
    .await;

    let mut state = state_with_beacons(
        &public_beacon,
        &operator_beacon,
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
    );
    Arc::make_mut(&mut state.config).zone_verifier = GatewayZoneVerifier::new("test-key");

    let external = Request::builder()
        .uri("/")
        .header("Host", "w33d.xyz")
        .header("X-Auth-Email", "alice@steadholme.local")
        .body(Body::empty())
        .unwrap();
    let (status, external_html) = call(&state, external).await;
    assert_eq!(status, StatusCode::OK);
    assert!(external_html.contains("1 of 1 systems operational"));
    assert!(external_html.contains(r#"1<span class="metric__unit">/1</span>"#));
    assert!(!external_html.contains("reporting issues: CA"));
    assert!(!external_html.contains("of 51 systems"));
    assert!(!external_html.contains(r#"/51</span>"#));
    assert!(!external_html.contains("Internal-"));

    let external_wire = Request::builder()
        .uri("/")
        .header("Host", "w33d.xyz")
        .header("X-Wire", "1")
        .body(Body::empty())
        .unwrap();
    let (status, external_fragment) = call(&state, external_wire).await;
    assert_eq!(status, StatusCode::OK);
    assert!(external_fragment.contains(r#"data-state="operational" data-up="1" data-total="1""#));
    assert!(!external_fragment.contains("reporting issues: CA"));
    assert!(!external_fragment.contains("of 51 systems"));
    assert!(!external_fragment.contains(r#"/51</span>"#));
    assert!(!external_fragment.contains("Internal-"));

    let signature = zone_signature("test-key", "w33d.xyz", "internal", current_minute());
    let internal = Request::builder()
        .uri("/")
        .header("Host", "w33d.xyz")
        .header("X-Auth-Email", "alice@steadholme.local")
        .header(HEADER_GATEWAY_ZONE, "internal")
        .header(HEADER_GATEWAY_ZONE_SIG, signature)
        .body(Body::empty())
        .unwrap();
    let (status, internal_html) = call(&state, internal).await;
    assert_eq!(status, StatusCode::OK);
    assert!(internal_html.contains("50 of 51 systems operational"));
    assert!(internal_html.contains("reporting issues: CA"));
    assert!(internal_html.contains(r#"50<span class="metric__unit">/51</span>"#));

    let (status, ops_html) = call(
        &state,
        get_as_groups("/ops", "root@steadholme.local", "infra-admins"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(ops_html.contains(r#"class="au-src" title="Down">CA</td>"#));
    assert!(ops_html.contains("Internal-49"));
}

#[tokio::test]
async fn dashboard_wire_response_is_exact_read_only_live_region() {
    let state = state_with(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
    );
    let request = Request::builder()
        .uri("/")
        .header("X-Auth-Email", "alice@steadholme.local")
        .header("X-Wire", "1")
        .body(Body::empty())
        .unwrap();
    let response = app(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("cache-control").unwrap(),
        "private, no-store"
    );
    assert_eq!(
        response.headers().get("vary").unwrap(),
        "X-Wire, X-Gateway-Zone, X-Gateway-Zone-Sig, X-Auth-Email"
    );
    assert!(response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let fragment = String::from_utf8_lossy(&bytes);

    assert!(fragment.starts_with(
        r#"<section class="estate-live" id="estate-live" role="region" aria-labelledby="estate-title""#
    ));
    assert!(fragment.contains(r#"data-access-scope="public""#));
    assert!(
        fragment.contains(r#"href="/?refresh=1#estate-live""#),
        "native GET fallback remains"
    );
    assert!(fragment.contains(r#"data-wire="get""#));
    assert!(fragment.contains(r##"data-wire-target="#estate-live""##));
    assert!(fragment.contains(r#"data-spark-reltime"#) || fragment.contains("No recent activity"));
    assert!(!fragment.contains("<!DOCTYPE html>"));
    assert!(!fragment.contains(r#"id="appsections""#));
    assert!(!fragment.contains("data-pin-button"));
    assert!(!fragment.contains(r#"id="cmdpalette""#));
    assert!(
        !fragment.contains("odyssey-wire v1"),
        "runtime stays in the full document"
    );
    assert!(
        !fragment.contains("csrf_token"),
        "read-only GET never receives CSRF markup"
    );
    assert!(!fragment.to_ascii_lowercase().contains("method=\"post\""));
}

#[tokio::test]
async fn dashboard_external_wire_fragment_hides_audit_event_targets() {
    let watchtower = fake_service(&[
        (
            "/api/verify",
            r#"{"ok":true,"count":1,"head_hash":"abc"}"#,
        ),
        (
            "/api/events",
            r#"[{"seq":1,"ts":1700000000000,"source":"vault","actor":"operator","action":"probe","target":"vault.w33d.xyz","severity":"info"}]"#,
        ),
    ])
    .await;
    let state = state_with("http://127.0.0.1:1", "http://127.0.0.1:1", &watchtower);

    let external = Request::builder()
        .uri("/")
        .header("X-Auth-Email", "alice@steadholme.local")
        .header("X-Wire", "1")
        .body(Body::empty())
        .unwrap();
    let (external_status, external_fragment) = call(&state, external).await;
    assert_eq!(external_status, StatusCode::OK);
    assert!(external_fragment.contains("Recent signals"));
    assert!(external_fragment.contains("probe"));
    assert!(
        !external_fragment.contains("vault.w33d.xyz"),
        "external fragments must not disclose arbitrary audit targets"
    );

    let internal = Request::builder()
        .uri("/")
        .header("X-Auth-Email", "alice@steadholme.local")
        .header("X-Gateway-Zone", "internal")
        .header("X-Wire", "1")
        .body(Body::empty())
        .unwrap();
    let (internal_status, internal_fragment) = call(&state, internal).await;
    assert_eq!(internal_status, StatusCode::OK);
    assert!(
        internal_fragment.contains("vault.w33d.xyz"),
        "the gateway-attested internal view keeps useful audit targets"
    );
}

#[tokio::test]
async fn dashboard_defines_no_mutation_route() {
    let state = state_with(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
    );
    let request = Request::builder()
        .method("POST")
        .uri("/")
        .body(Body::empty())
        .unwrap();
    let (status, _) = call(&state, request).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn dashboard_refresh_fallback_returns_a_complete_document() {
    let state = state_with(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
    );
    let (status, html) = call(&state, get("/?refresh=1")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains(r#"id="estate-live""#));
    assert!(html.contains(r#"id="appsections""#));
}

#[tokio::test]
async fn dashboard_incident_banner_uses_down_variant() {
    let beacon = fake_service(&[(
        "/api/status",
        r#"{"overall":"down","updated_at":1,"components":[
            {"name":"Identity","kind":"tcp","status":"down","uptime_24h":92.0},
            {"name":"Gateway","kind":"http","status":"degraded","uptime_24h":97.0}
        ],"incidents":[]}"#,
    )])
    .await;
    let state = state_with(&beacon, "http://127.0.0.1:1", "http://127.0.0.1:1");

    let (status, html) = call(&state, get_as("/", "alice@steadholme.local")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(r#"class="incidentbar incidentbar--down""#),
        "any down component escalates the incident banner"
    );
    assert!(
        html.contains(r#"title="Down""#),
        "down tiles keep a title channel"
    );
    assert!(
        html.contains(r#"aria-label="Down""#),
        "down tiles keep an aria channel"
    );
}

#[tokio::test]
async fn dashboard_search_query_filters_server_side() {
    let state = state_with(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
    );

    let (status, html) = call(&state, get_as("/?q=webmail", "alice@steadholme.local")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(r#"value="webmail""#),
        "search value is echoed"
    );
    assert!(
        html.contains("https://mail.w33d.xyz"),
        "matching app remains"
    );
    assert!(
        !html.contains("https://blog.w33d.xyz"),
        "non-matching app is filtered out"
    );
    assert!(
        html.contains("Communication"),
        "single search result keeps its semantic field band"
    );

    let (status, html) = call(&state, get_as("/?q=no-such-app", "alice@steadholme.local")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("No apps match &ldquo;no-such-app&rdquo;."),
        "empty SSR search result is visible without JavaScript"
    );
}

#[tokio::test]
async fn dashboard_internal_gateway_zone_renders_mgmt_consoles() {
    let beacon = fake_service(&[(
        "/api/status",
        r#"{"overall":"degraded","updated_at":1,"components":[
            {"name":"Authz","kind":"http","status":"operational","uptime_24h":100.0},
            {"name":"Mycelium","kind":"http","status":"degraded","uptime_24h":97.0}
        ],"incidents":[]}"#,
    )])
    .await;
    let state = state_with(&beacon, "http://127.0.0.1:1", "http://127.0.0.1:1");

    let (status, html) = call(
        &state,
        get_as_zone("/", "alice@steadholme.local", "internal"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        html.contains(r##"href="#infraops" data-spy="infraops""##),
        "internal sidebar links to the mgmt section"
    );
    assert!(
        html.contains(r#"id="infraops" data-access-scope="internal""#),
        "internal mgmt section rendered"
    );
    assert!(
        html.contains("Infrastructure &amp; Operations"),
        "mgmt section title is escaped and visible"
    );
    assert!(
        html.contains(r#"data-internal-surface-count="27""#),
        "all internal consoles are represented in the attested view"
    );
    assert!(
        html.contains("27 management surfaces")
            && html.contains("Observe")
            && html.contains("Protect")
            && html.contains("Network")
            && html.contains("Recover"),
        "the gateway-attested WireGuard plane is summarized"
    );

    for (name, url) in [
        ("Authorization", "https://authz.w33d.xyz"),
        ("Directory", "https://people.w33d.xyz"),
        ("Vault", "https://vault.w33d.xyz"),
        ("Audit log", "https://audit.w33d.xyz"),
        ("Logs", "https://logs.w33d.xyz"),
        ("Traces", "https://traces.w33d.xyz"),
        ("DNS", "https://dns.w33d.xyz"),
        ("Deploy", "https://deploy.w33d.xyz"),
        ("Egress", "https://egress.w33d.xyz"),
        ("SPIFFE", "https://spiffe.w33d.xyz"),
        ("Purple", "https://purple.w33d.xyz"),
        ("Detonate", "https://detonate.w33d.xyz"),
        ("VPN enrollment", "https://vpn.w33d.xyz"),
    ] {
        assert!(html.contains(name), "{name} mgmt tile rendered");
        assert!(html.contains(url), "{name} links to {url}");
    }

    assert!(
        html.contains(r#"data-app-id="https://vpn.w33d.xyz""#),
        "mgmt tiles participate in launcher JS"
    );
    assert!(
        !html.contains(r#"title="Operational""#),
        "operational mgmt tiles are silent"
    );
    assert!(
        html.contains(r#"title="Degraded""#),
        "Mycelium component status maps through Beacon"
    );
}

#[tokio::test]
async fn dashboard_public_gateway_zone_is_byte_identical_without_mgmt() {
    let state = state_with(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
    );

    let (missing_status, missing) = call(&state, get_as("/", "eve@steadholme.local")).await;
    let (external_status, external) =
        call(&state, get_as_zone("/", "eve@steadholme.local", "external")).await;
    let (wrong_case_status, wrong_case) =
        call(&state, get_as_zone("/", "eve@steadholme.local", "Internal")).await;

    assert_eq!(missing_status, StatusCode::OK);
    assert_eq!(external_status, StatusCode::OK);
    assert_eq!(wrong_case_status, StatusCode::OK);
    assert_eq!(
        external, missing,
        "external zone is byte-identical to the public view"
    );
    assert_eq!(
        wrong_case, missing,
        "only the exact internal zone value unlocks mgmt consoles"
    );

    for forbidden in [
        "Infrastructure &amp; Operations",
        "27 management surfaces",
        "https://authz.w33d.xyz",
        "https://vault.w33d.xyz",
        "https://vpn.w33d.xyz",
        r##"href="#infraops" data-spy="infraops""##,
    ] {
        assert!(
            !missing.contains(forbidden),
            "{forbidden} is absent from public dashboard"
        );
    }
    assert!(
        missing.contains("WireGuard required")
            && missing.contains("Management hostnames stay hidden"),
        "external users see the access contract without internal route disclosure"
    );
}

#[tokio::test]
async fn dashboard_is_resilient_when_all_backends_down() {
    // Point every backend at a closed port: each fetch fails fast and the page still renders.
    let state = state_with(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
    );

    let (status, html) = call(&state, get_as("/", "bob@steadholme.local")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "page renders even when every backend is down"
    );
    assert!(
        html.contains("bob@steadholme.local"),
        "email still rendered"
    );

    // Unknown tile status stays silent while placeholders continue to degrade gracefully.
    assert!(
        !html.contains(r#"title="Unknown""#),
        "down Beacon does not render Unknown status dots"
    );
    assert!(
        !html.contains(r#"class="app__status"#),
        "down Beacon does not render tile status nodes"
    );
    assert!(
        html.contains("—"),
        "missing metrics render the em-dash placeholder"
    );
    assert!(
        html.contains("awaiting Beacon"),
        "systems card degrades gracefully"
    );
    assert!(
        html.contains("awaiting Vitals"),
        "gauges degrade gracefully"
    );
    assert!(
        html.contains("awaiting Watchtower"),
        "audit card degrades gracefully"
    );
    assert!(
        html.contains("No recent activity"),
        "empty activity feed placeholder"
    );
    // App tiles still render regardless of backend health (status just degrades to Unknown).
    assert!(
        html.contains("https://mail.w33d.xyz"),
        "app grid renders even when backends are down"
    );
}

#[tokio::test]
async fn ops_console_forbidden_for_non_admin() {
    // A signed-in user with no admin group (or none at all) must get a 403 on /ops; the public
    // dashboard is unaffected.
    let state = state_with(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
    );

    // No groups at all.
    let (status, _) = call(&state, get_as("/ops", "eve@steadholme.local")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no groups -> 403 on /ops");

    // A non-admin group.
    let (status, _) = call(
        &state,
        get_as_groups("/ops", "eve@steadholme.local", "readers,writers"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-admin group -> 403 on /ops"
    );

    // The public dashboard stays open to the same non-admin user.
    let (dash, _) = call(&state, get_as("/", "eve@steadholme.local")).await;
    assert_eq!(
        dash,
        StatusCode::OK,
        "public dashboard unchanged for non-admins"
    );
}

#[tokio::test]
async fn ops_console_renders_for_admin() {
    let beacon = fake_service(&[(
        "/api/status",
        r#"{"overall":"degraded","updated_at":1,"components":[
            {"name":"Identity","kind":"tcp","status":"operational","uptime_24h":99.98},
            {"name":"Gateway","kind":"http","status":"degraded","uptime_24h":97.5}
        ],"incidents":[]}"#,
    )])
    .await;
    let vitals = fake_service(&[(
        "/api/metrics",
        r#"{"samples":[
            {"host":"h","metric":"cpu_pct","value":21.0,"ts":200},
            {"host":"h","metric":"mem_pct","value":55.0,"ts":200},
            {"host":"h","metric":"load1","value":0.42,"ts":200}
        ]}"#,
    )])
    .await;
    let watchtower = fake_service(&[
        ("/api/verify", r#"{"ok":true,"count":7,"head_hash":"deadbeefcafe0001"}"#),
        (
            "/api/events",
            r#"[
              {"seq":7,"ts":1700000000000,"source":"keystone","actor":"alice@steadholme.local","action":"login","target":"sso","severity":"info"},
              {"seq":6,"ts":1699999000000,"source":"relay","actor":"bob@steadholme.local","action":"key.revoke","target":"relay_sk_x","severity":"warning"}
            ]"#,
        ),
    ])
    .await;

    let state = state_with(&beacon, &vitals, &watchtower);
    let (status, html) = call(
        &state,
        get_as_groups("/ops", "root@steadholme.local", "infra-admins"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin group unlocks /ops");

    // Audit viewer: verify summary + per-event rows (source/actor/action all present).
    assert!(
        html.contains("Cross-service audit"),
        "audit section rendered"
    );
    assert!(
        html.contains("7 sealed"),
        "chain count in the audit summary"
    );
    assert!(html.contains("chain verified"), "integrity flag shown");
    assert!(html.contains("keystone"), "event source rendered");
    assert!(html.contains("key.revoke"), "event action rendered");
    assert!(html.contains(r#"class="au-row""#), "audit rows rendered");
    assert!(
        html.contains(r#"data-sev="warning""#),
        "severity filter key on the row"
    );

    // Per-service health table: name + status + uptime.
    assert!(html.contains("Service health"), "health section rendered");
    assert!(
        html.contains("Identity"),
        "component name in the health table"
    );
    assert!(html.contains("99.98%"), "component 24h uptime rendered");
    assert!(
        html.contains("Operational"),
        "live status pill in the health table"
    );

    // Host metrics from Vitals.
    assert!(html.contains("Host CPU"), "host metric tiles present");
    assert!(html.contains("21%"), "cpu gauge");
    assert!(html.contains("0.42"), "load average");
}

#[tokio::test]
async fn ops_console_resilient_when_backends_down() {
    // Admin hits /ops but every backend is down: the console renders (200) with graceful
    // placeholders rather than erroring.
    let state = state_with(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
    );
    let (status, html) = call(
        &state,
        get_as_groups("/ops", "root@steadholme.local", "admins"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "console renders even with every backend down"
    );
    assert!(
        html.contains("No audit events to show."),
        "empty audit placeholder"
    );
    assert!(
        html.contains("Beacon has not reported component health yet."),
        "empty health placeholder"
    );
}

/// Fake Watchtower with three distinct sealed events (different sources/actors/actions and
/// timestamps 1700000000000..1700000200000 ms) for the audit filter tests.
async fn watchtower_with_three_events() -> String {
    fake_service(&[
        ("/api/verify", r#"{"ok":true,"count":3,"head_hash":"abc"}"#),
        (
            "/api/events",
            r#"[
              {"seq":3,"ts":1700000200000,"source":"keystone","actor":"alice@steadholme.local","action":"login","target":"sso","severity":"info","detail":"ok","prev_hash":"p3","hash":"h3"},
              {"seq":2,"ts":1700000100000,"source":"relay","actor":"bob@steadholme.local","action":"key.revoke","target":"relay_sk","severity":"warning","detail":"<script>alert(1)</script>","prev_hash":"p2","hash":"h2"},
              {"seq":1,"ts":1700000000000,"source":"keystone","actor":"carol@steadholme.local","action":"logout","target":"sso","severity":"info","detail":"","prev_hash":"p1","hash":"h1"}
            ]"#,
        ),
    ])
    .await
}

fn audit_row_count(html: &str) -> usize {
    html.matches(r#"class="au-row""#).count()
}

#[tokio::test]
async fn ops_gate_holds_with_audit_query_params() {
    // The admin gate is evaluated before any query handling: filters/pagination params never
    // widen access.
    let state = state_with(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
    );
    let (status, _) = call(
        &state,
        get_as_groups(
            "/ops?actor=alice&range=7d&page=2",
            "eve@steadholme.local",
            "readers",
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-admin stays 403 with query params"
    );

    let (status, _) = call(&state, get_as("/ops?actor=alice", "eve@steadholme.local")).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "no groups stays 403 with query params"
    );

    let (status, _) = call(
        &state,
        get_as_groups(
            "/ops?actor=alice&page=99",
            "root@steadholme.local",
            "admins",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin passes with any query params");
}

#[tokio::test]
async fn ops_audit_filters_apply_server_side() {
    let watchtower = watchtower_with_three_events().await;
    let state = state_with("http://127.0.0.1:1", "http://127.0.0.1:1", &watchtower);

    // Actor substring + source substring narrow to the single matching event.
    let (status, html) = call(
        &state,
        get_as_groups(
            "/ops?actor=alice&source=key",
            "root@steadholme.local",
            "admins",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(audit_row_count(&html), 1, "one matching row rendered");
    assert!(
        html.contains("alice@steadholme.local"),
        "matching actor rendered"
    );
    assert!(
        !html.contains("bob@steadholme.local"),
        "non-matching actor filtered out"
    );
    assert!(
        html.contains("showing 1"),
        "summary counts the filtered result"
    );
    assert!(
        html.contains(r#"value="alice""#),
        "filter value echoed in the form"
    );

    // Action substring filter.
    let (_, html) = call(
        &state,
        get_as_groups("/ops?action=revoke", "root@steadholme.local", "admins"),
    )
    .await;
    assert_eq!(audit_row_count(&html), 1);
    assert!(html.contains("key.revoke"), "matching action rendered");
    assert!(
        !html.contains("carol@steadholme.local"),
        "non-matching event filtered out"
    );

    // A filter value with HTML is echoed ESCAPED, never raw, and matches nothing.
    let (_, html) = call(
        &state,
        get_as_groups("/ops?actor=%3Cscript%3E", "root@steadholme.local", "admins"),
    )
    .await;
    assert!(
        html.contains(r#"value="&lt;script&gt;""#),
        "filter echo is escaped"
    );
    assert!(!html.contains(r#"value="<script>"#), "no raw HTML echo");
    assert_eq!(audit_row_count(&html), 0);
    assert!(
        html.contains("No audit events to show."),
        "empty filtered table"
    );
    assert!(
        html.contains("No events match the current filters."),
        "pager explains"
    );
}

#[tokio::test]
async fn ops_audit_time_range_filters() {
    let watchtower = watchtower_with_three_events().await;
    let state = state_with("http://127.0.0.1:1", "http://127.0.0.1:1", &watchtower);

    // Custom epoch bounds (SECONDS) keep only the oldest event (ts 1700000000000 ms).
    let (status, html) = call(
        &state,
        get_as_groups(
            "/ops?range=custom&from=1700000000&to=1700000050",
            "root@steadholme.local",
            "admins",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(audit_row_count(&html), 1, "custom range keeps one event");
    assert!(
        html.contains("carol@steadholme.local"),
        "the in-range event rendered"
    );
    assert!(
        !html.contains("alice@steadholme.local"),
        "later events excluded"
    );
    assert!(
        html.contains(r#"value="1700000000""#),
        "custom bound echoed in the form"
    );
    assert!(
        html.contains(r#"<option value="custom" selected>"#),
        "preset stays selected"
    );

    // A relative preset (24h): the canned 2023 events are all older -> nothing matches.
    let (_, html) = call(
        &state,
        get_as_groups("/ops?range=24h", "root@steadholme.local", "admins"),
    )
    .await;
    assert_eq!(
        audit_row_count(&html),
        0,
        "preset window excludes old events"
    );
    assert!(
        html.contains(r#"<option value="24h" selected>"#),
        "preset stays selected"
    );
}

#[tokio::test]
async fn ops_audit_pagination_preserves_filters() {
    // 30 events for one actor -> 25 on page 1, 5 on page 2, links carrying the filter.
    let mut items = String::from("[");
    for i in 0..30 {
        if i > 0 {
            items.push(',');
        }
        items.push_str(&format!(
            r#"{{"seq":{seq},"ts":{ts},"source":"keystone","actor":"page.user@steadholme.local","action":"act.{i}","target":"t","severity":"info","detail":"d","prev_hash":"p","hash":"h"}}"#,
            seq = 30 - i,
            ts = 1_700_000_000_000i64 - i as i64,
        ));
    }
    items.push(']');
    let routes: &'static [(&'static str, &'static str)] = Box::leak(
        vec![
            (
                "/api/verify",
                r#"{"ok":true,"count":30,"head_hash":"abc"}"# as &'static str,
            ),
            (
                "/api/events",
                Box::leak(items.into_boxed_str()) as &'static str,
            ),
        ]
        .into_boxed_slice(),
    );
    let watchtower = fake_service(routes).await;
    let state = state_with("http://127.0.0.1:1", "http://127.0.0.1:1", &watchtower);

    let (status, html) = call(
        &state,
        get_as_groups("/ops?actor=page.user", "root@steadholme.local", "admins"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(audit_row_count(&html), 25, "page 1 shows PAGE_SIZE rows");
    assert!(html.contains("Page 1 of 2 · 30 events"), "pager summary");
    assert!(
        html.contains(r#"href="/ops?actor=page.user&amp;page=2#audit""#),
        "next link preserves the filter, ampersand-escaped"
    );
    assert!(
        !html.contains("&larr; Prev"),
        "no prev link on the first page"
    );

    let (_, html) = call(
        &state,
        get_as_groups(
            "/ops?actor=page.user&page=2",
            "root@steadholme.local",
            "admins",
        ),
    )
    .await;
    assert_eq!(audit_row_count(&html), 5, "page 2 shows the remainder");
    assert!(html.contains("Page 2 of 2 · 30 events"), "pager summary");
    assert!(
        html.contains(r#"href="/ops?actor=page.user&amp;page=1#audit""#),
        "prev link preserves the filter, ampersand-escaped"
    );
    assert!(
        html.contains("act.29"),
        "page 2 renders the tail of the stream"
    );
    assert!(
        !html.contains(r#"<td class="au-action">act.0</td>"#),
        "page 1 rows not repeated"
    );

    // An out-of-range page clamps to the last page instead of erroring.
    let (status, html) = call(
        &state,
        get_as_groups(
            "/ops?actor=page.user&page=99",
            "root@steadholme.local",
            "admins",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("Page 2 of 2"),
        "overshoot clamps to the last page"
    );
}

#[tokio::test]
async fn ops_event_detail_expands_full_metadata_escaped() {
    let watchtower = watchtower_with_three_events().await;
    let state = state_with("http://127.0.0.1:1", "http://127.0.0.1:1", &watchtower);
    let (status, html) = call(
        &state,
        get_as_groups("/ops", "root@steadholme.local", "admins"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Every row carries a no-JS <details> expander with the full sealed metadata.
    assert!(
        html.contains(r#"<details class="au-detail">"#),
        "detail expander rendered"
    );
    assert!(
        html.contains("<dt>Seq</dt><dd>2</dd>"),
        "sequence number shown"
    );
    assert!(
        html.contains("1700000100000 ms"),
        "raw epoch-ms timestamp shown"
    );
    assert!(
        html.contains("<dt>Prev hash</dt><dd>p2</dd>"),
        "chain prev hash shown"
    );
    assert!(
        html.contains("<dt>Hash</dt><dd>h2</dd>"),
        "chain hash shown"
    );
    // The free-text detail payload is HTML-escaped, never raw.
    assert!(
        html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "detail payload escaped"
    );
    assert!(
        !html.contains("<script>alert(1)</script>"),
        "no raw payload HTML"
    );
}

#[tokio::test]
async fn dashboard_without_gateway_identity_falls_back() {
    // No X-Auth-Email (e.g. a direct dev hit) — the page renders with a generic label,
    // never erroring on the missing identity.
    let state = state_with(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
    );
    let (status, html) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("operator"),
        "falls back to a generic signed-in label"
    );
    assert!(
        html.contains(r#"data-user-name="Operator">Operator</span>"#),
        "greeting falls back gracefully"
    );
}
