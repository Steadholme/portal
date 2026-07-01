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
async fn ops_console_forbidden_for_non_admin() {
    // A signed-in user with no admin group (or none at all) must get a 403 on /ops; the public
    // dashboard is unaffected.
    let state = state_with("http://127.0.0.1:1", "http://127.0.0.1:1", "http://127.0.0.1:1");

    // No groups at all.
    let (status, _) = call(&state, get_as("/ops", "eve@holdfast.local")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no groups -> 403 on /ops");

    // A non-admin group.
    let (status, _) =
        call(&state, get_as_groups("/ops", "eve@holdfast.local", "readers,writers")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-admin group -> 403 on /ops");

    // The public dashboard stays open to the same non-admin user.
    let (dash, _) = call(&state, get_as("/", "eve@holdfast.local")).await;
    assert_eq!(dash, StatusCode::OK, "public dashboard unchanged for non-admins");
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
              {"seq":7,"ts":1700000000000,"source":"keystone","actor":"alice@holdfast.local","action":"login","target":"sso","severity":"info"},
              {"seq":6,"ts":1699999000000,"source":"relay","actor":"bob@holdfast.local","action":"key.revoke","target":"relay_sk_x","severity":"warning"}
            ]"#,
        ),
    ])
    .await;

    let state = state_with(&beacon, &vitals, &watchtower);
    let (status, html) =
        call(&state, get_as_groups("/ops", "root@holdfast.local", "infra-admins")).await;
    assert_eq!(status, StatusCode::OK, "admin group unlocks /ops");

    // Audit viewer: verify summary + per-event rows (source/actor/action all present).
    assert!(html.contains("Cross-service audit"), "audit section rendered");
    assert!(html.contains("7 sealed"), "chain count in the audit summary");
    assert!(html.contains("chain verified"), "integrity flag shown");
    assert!(html.contains("keystone"), "event source rendered");
    assert!(html.contains("key.revoke"), "event action rendered");
    assert!(html.contains(r#"class="au-row""#), "audit rows rendered");
    assert!(html.contains(r#"data-sev="warning""#), "severity filter key on the row");

    // Per-service health table: name + status + uptime.
    assert!(html.contains("Service health"), "health section rendered");
    assert!(html.contains("Identity"), "component name in the health table");
    assert!(html.contains("99.98%"), "component 24h uptime rendered");
    assert!(html.contains("Operational"), "live status pill in the health table");

    // Host metrics from Vitals.
    assert!(html.contains("Host CPU"), "host metric tiles present");
    assert!(html.contains("21%"), "cpu gauge");
    assert!(html.contains("0.42"), "load average");
}

#[tokio::test]
async fn ops_console_resilient_when_backends_down() {
    // Admin hits /ops but every backend is down: the console renders (200) with graceful
    // placeholders rather than erroring.
    let state = state_with("http://127.0.0.1:1", "http://127.0.0.1:1", "http://127.0.0.1:1");
    let (status, html) =
        call(&state, get_as_groups("/ops", "root@holdfast.local", "admins")).await;
    assert_eq!(status, StatusCode::OK, "console renders even with every backend down");
    assert!(html.contains("No audit events to show."), "empty audit placeholder");
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
              {"seq":3,"ts":1700000200000,"source":"keystone","actor":"alice@holdfast.local","action":"login","target":"sso","severity":"info","detail":"ok","prev_hash":"p3","hash":"h3"},
              {"seq":2,"ts":1700000100000,"source":"relay","actor":"bob@holdfast.local","action":"key.revoke","target":"relay_sk","severity":"warning","detail":"<script>alert(1)</script>","prev_hash":"p2","hash":"h2"},
              {"seq":1,"ts":1700000000000,"source":"keystone","actor":"carol@holdfast.local","action":"logout","target":"sso","severity":"info","detail":"","prev_hash":"p1","hash":"h1"}
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
    let state = state_with("http://127.0.0.1:1", "http://127.0.0.1:1", "http://127.0.0.1:1");
    let (status, _) = call(
        &state,
        get_as_groups("/ops?actor=alice&range=7d&page=2", "eve@holdfast.local", "readers"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-admin stays 403 with query params");

    let (status, _) = call(&state, get_as("/ops?actor=alice", "eve@holdfast.local")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no groups stays 403 with query params");

    let (status, _) = call(
        &state,
        get_as_groups("/ops?actor=alice&page=99", "root@holdfast.local", "admins"),
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
        get_as_groups("/ops?actor=alice&source=key", "root@holdfast.local", "admins"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(audit_row_count(&html), 1, "one matching row rendered");
    assert!(html.contains("alice@holdfast.local"), "matching actor rendered");
    assert!(!html.contains("bob@holdfast.local"), "non-matching actor filtered out");
    assert!(html.contains("showing 1"), "summary counts the filtered result");
    assert!(html.contains(r#"value="alice""#), "filter value echoed in the form");

    // Action substring filter.
    let (_, html) = call(
        &state,
        get_as_groups("/ops?action=revoke", "root@holdfast.local", "admins"),
    )
    .await;
    assert_eq!(audit_row_count(&html), 1);
    assert!(html.contains("key.revoke"), "matching action rendered");
    assert!(!html.contains("carol@holdfast.local"), "non-matching event filtered out");

    // A filter value with HTML is echoed ESCAPED, never raw, and matches nothing.
    let (_, html) = call(
        &state,
        get_as_groups("/ops?actor=%3Cscript%3E", "root@holdfast.local", "admins"),
    )
    .await;
    assert!(html.contains(r#"value="&lt;script&gt;""#), "filter echo is escaped");
    assert!(!html.contains(r#"value="<script>"#), "no raw HTML echo");
    assert_eq!(audit_row_count(&html), 0);
    assert!(html.contains("No audit events to show."), "empty filtered table");
    assert!(html.contains("No events match the current filters."), "pager explains");
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
            "root@holdfast.local",
            "admins",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(audit_row_count(&html), 1, "custom range keeps one event");
    assert!(html.contains("carol@holdfast.local"), "the in-range event rendered");
    assert!(!html.contains("alice@holdfast.local"), "later events excluded");
    assert!(html.contains(r#"value="1700000000""#), "custom bound echoed in the form");
    assert!(html.contains(r#"<option value="custom" selected>"#), "preset stays selected");

    // A relative preset (24h): the canned 2023 events are all older -> nothing matches.
    let (_, html) = call(
        &state,
        get_as_groups("/ops?range=24h", "root@holdfast.local", "admins"),
    )
    .await;
    assert_eq!(audit_row_count(&html), 0, "preset window excludes old events");
    assert!(html.contains(r#"<option value="24h" selected>"#), "preset stays selected");
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
            r#"{{"seq":{seq},"ts":{ts},"source":"keystone","actor":"page.user@holdfast.local","action":"act.{i}","target":"t","severity":"info","detail":"d","prev_hash":"p","hash":"h"}}"#,
            seq = 30 - i,
            ts = 1_700_000_000_000i64 - i as i64,
        ));
    }
    items.push(']');
    let routes: &'static [(&'static str, &'static str)] = Box::leak(
        vec![
            ("/api/verify", r#"{"ok":true,"count":30,"head_hash":"abc"}"# as &'static str),
            ("/api/events", Box::leak(items.into_boxed_str()) as &'static str),
        ]
        .into_boxed_slice(),
    );
    let watchtower = fake_service(routes).await;
    let state = state_with("http://127.0.0.1:1", "http://127.0.0.1:1", &watchtower);

    let (status, html) = call(
        &state,
        get_as_groups("/ops?actor=page.user", "root@holdfast.local", "admins"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(audit_row_count(&html), 25, "page 1 shows PAGE_SIZE rows");
    assert!(html.contains("Page 1 of 2 · 30 events"), "pager summary");
    assert!(
        html.contains(r#"href="/ops?actor=page.user&amp;page=2#audit""#),
        "next link preserves the filter, ampersand-escaped"
    );
    assert!(!html.contains("&larr; Prev"), "no prev link on the first page");

    let (_, html) = call(
        &state,
        get_as_groups("/ops?actor=page.user&page=2", "root@holdfast.local", "admins"),
    )
    .await;
    assert_eq!(audit_row_count(&html), 5, "page 2 shows the remainder");
    assert!(html.contains("Page 2 of 2 · 30 events"), "pager summary");
    assert!(
        html.contains(r#"href="/ops?actor=page.user&amp;page=1#audit""#),
        "prev link preserves the filter, ampersand-escaped"
    );
    assert!(html.contains("act.29"), "page 2 renders the tail of the stream");
    assert!(!html.contains(r#"<td class="au-action">act.0</td>"#), "page 1 rows not repeated");

    // An out-of-range page clamps to the last page instead of erroring.
    let (status, html) = call(
        &state,
        get_as_groups("/ops?actor=page.user&page=99", "root@holdfast.local", "admins"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Page 2 of 2"), "overshoot clamps to the last page");
}

#[tokio::test]
async fn ops_event_detail_expands_full_metadata_escaped() {
    let watchtower = watchtower_with_three_events().await;
    let state = state_with("http://127.0.0.1:1", "http://127.0.0.1:1", &watchtower);
    let (status, html) =
        call(&state, get_as_groups("/ops", "root@holdfast.local", "admins")).await;
    assert_eq!(status, StatusCode::OK);

    // Every row carries a no-JS <details> expander with the full sealed metadata.
    assert!(html.contains(r#"<details class="au-detail">"#), "detail expander rendered");
    assert!(html.contains("<dt>Seq</dt><dd>2</dd>"), "sequence number shown");
    assert!(html.contains("1700000100000 ms"), "raw epoch-ms timestamp shown");
    assert!(html.contains("<dt>Prev hash</dt><dd>p2</dd>"), "chain prev hash shown");
    assert!(html.contains("<dt>Hash</dt><dd>h2</dd>"), "chain hash shown");
    // The free-text detail payload is HTML-escaped, never raw.
    assert!(
        html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "detail payload escaped"
    );
    assert!(!html.contains("<script>alert(1)</script>"), "no raw payload HTML");
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
