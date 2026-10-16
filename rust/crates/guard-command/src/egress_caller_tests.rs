use super::*;
use std::io::Read;
use std::net::TcpListener;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

/// Serve `responses` in order on loopback; returns the base URL and the raw
/// requests seen.
fn serve(responses: Vec<String>) -> (String, Arc<Mutex<Vec<String>>>, Arc<AtomicU32>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let hits = Arc::new(AtomicU32::new(0));
    let (seen_thread, hits_thread) = (seen.clone(), hits.clone());
    std::thread::spawn(move || {
        for response in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 8192];
            let read = stream.read(&mut buf).unwrap_or(0);
            seen_thread
                .lock()
                .expect("lock")
                .push(String::from_utf8_lossy(&buf[..read]).into_owned());
            hits_thread.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (base, seen, hits)
}

fn ok(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn moved(location: &str) -> String {
    format!(
        "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    )
}

fn need(url: &str) -> EgressNeedV1 {
    EgressNeedV1 {
        class: "registry".to_owned(),
        method: "GET".to_owned(),
        url: url.to_owned(),
        headers: BTreeMap::new(),
        body: None,
        body_sha256: String::new(),
        occurrence: 1,
        timeout_seconds: 5.0,
        max_redirects: 0,
        max_response_bytes: 1024 * 1024,
        delay_seconds: 0.0,
        inspect: None,
    }
}

fn spool_dir(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("egress-caller-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("spool dir");
    path
}

fn fulfil(needs: &[EgressNeedV1], spool: &Path) -> Vec<EgressSuppliedV1> {
    let mut fulfilment = EgressFulfilment::new(spool, &UnmanagedEgressPolicy);
    fulfilment.fulfil(needs).expect("fulfil");
    fulfilment.supplied().to_vec()
}

#[test]
fn a_small_response_is_inlined_and_keyed_by_the_need() {
    let (base, _seen, _hits) = serve(vec![ok("{\"dist-tags\":{}}")]);
    let spool = spool_dir("inline");
    let mut asked = need(&format!("{base}/left-pad"));
    asked.occurrence = 3;
    asked.body_sha256 = "a".repeat(64);
    let supplied = fulfil(&[asked.clone()], &spool);
    assert_eq!(supplied.len(), 1);
    assert_eq!(supplied[0].class, "registry");
    assert_eq!(supplied[0].method, "GET");
    assert_eq!(supplied[0].url, asked.url);
    assert_eq!(supplied[0].body_sha256, asked.body_sha256);
    assert_eq!(supplied[0].occurrence, 3);
    let EgressOutcomeV1::Response {
        status,
        headers,
        body,
        body_file,
    } = &supplied[0].outcome
    else {
        panic!("{:?}", supplied[0].outcome);
    };
    assert_eq!(*status, 200);
    assert_eq!(body.as_deref(), Some("{\"dist-tags\":{}}"));
    assert!(body_file.is_none());
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
}

#[test]
fn a_body_past_the_inline_cap_is_spooled_beside_the_request() {
    let large = "x".repeat(EGRESS_MAX_INLINE_BODY_BYTES + 1);
    let (base, _seen, _hits) = serve(vec![ok(&large)]);
    let spool = spool_dir("spool");
    let supplied = fulfil(&[need(&format!("{base}/big"))], &spool);
    let EgressOutcomeV1::Response {
        body, body_file, ..
    } = &supplied[0].outcome
    else {
        panic!("{:?}", supplied[0].outcome);
    };
    assert!(body.is_none());
    let name = body_file.clone().expect("body file");
    assert_eq!(name, "body-1");
    assert_eq!(
        std::fs::read(spool.join(name)).expect("spooled"),
        large.as_bytes()
    );
}

#[test]
fn a_body_over_the_needs_cap_is_an_error_not_a_truncated_answer() {
    let (base, _seen, _hits) = serve(vec![ok("0123456789")]);
    let spool = spool_dir("cap");
    let mut asked = need(&format!("{base}/big"));
    asked.max_response_bytes = 4;
    let supplied = fulfil(&[asked], &spool);
    let EgressOutcomeV1::Error { message } = &supplied[0].outcome else {
        panic!("{:?}", supplied[0].outcome);
    };
    assert_eq!(message, "response too large");
}

#[test]
fn a_redirect_is_followed_only_within_the_budget_the_need_allows() {
    let (base, _seen, hits) = serve(vec![moved("/moved"), ok("{}"), moved("/again")]);
    let spool = spool_dir("redirect");
    let mut asked = need(&format!("{base}/start"));
    asked.max_redirects = 1;
    let supplied = fulfil(&[asked.clone()], &spool);
    assert!(
        matches!(&supplied[0].outcome, EgressOutcomeV1::Response { status, .. } if *status == 200),
        "{:?}",
        supplied[0].outcome
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    // The third response redirects again, past the budget of one hop.
    let (base, _seen, _hits) = serve(vec![moved("/one"), moved("/two")]);
    let mut asked = need(&format!("{base}/start"));
    asked.max_redirects = 1;
    let supplied = fulfil(&[asked], &spool);
    let EgressOutcomeV1::Error { message } = &supplied[0].outcome else {
        panic!("{:?}", supplied[0].outcome);
    };
    assert_eq!(message, "too many redirects");
}

#[test]
fn a_credentialled_or_bodied_request_is_never_redirected() {
    let (base, _seen, hits) = serve(vec![moved("/moved"), ok("{}")]);
    let spool = spool_dir("credential");
    let mut asked = need(&format!("{base}/start"));
    asked.max_redirects = 3;
    asked
        .headers
        .insert("Authorization".to_owned(), "DPoP token".to_owned());
    let supplied = fulfil(&[asked], &spool);
    assert!(
        matches!(&supplied[0].outcome, EgressOutcomeV1::Response { status, .. } if *status == 302),
        "{:?}",
        supplied[0].outcome
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(redirect_budget("GET", false, &BTreeMap::new(), 3), 3);
    assert_eq!(redirect_budget("POST", false, &BTreeMap::new(), 3), 0);
    assert_eq!(redirect_budget("GET", true, &BTreeMap::new(), 3), 0);
    assert_eq!(redirect_budget("GET", false, &BTreeMap::new(), 99), 10);
}

#[test]
fn a_refused_scheme_or_destination_is_blocked_without_a_request() {
    let spool = spool_dir("blocked");
    let supplied = fulfil(&[need("file:///etc/passwd")], &spool);
    assert_eq!(
        supplied[0].outcome,
        EgressOutcomeV1::Blocked {
            code: "egress_scheme_not_allowed".to_owned()
        }
    );

    struct Refusing;
    impl EgressPolicy for Refusing {
        fn validate(&self, _url: &str) -> Result<(), String> {
            Err("managed_public_registry_disabled".to_owned())
        }
    }
    let mut fulfilment = EgressFulfilment::new(&spool, &Refusing);
    fulfilment
        .fulfil(&[need("https://registry.npmjs.org/left-pad")])
        .expect("fulfil");
    assert_eq!(
        fulfilment.supplied()[0].outcome,
        EgressOutcomeV1::Blocked {
            code: "managed_public_registry_disabled".to_owned()
        }
    );
}

#[test]
fn an_archive_need_reports_that_acquisition_is_unavailable() {
    let spool = spool_dir("archive");
    let mut asked = need("https://example.com/pkg.tgz");
    asked.class = "archive".to_owned();
    let supplied = fulfil(&[asked], &spool);
    assert!(
        matches!(&supplied[0].outcome, EgressOutcomeV1::ArchiveFailure { code, .. }
            if code == "external_archive_download_unavailable"),
        "{:?}",
        supplied[0].outcome
    );
}

#[test]
fn the_rounds_bounds_hold() {
    let spool = spool_dir("bounds");
    let mut fulfilment = EgressFulfilment::new(&spool, &UnmanagedEgressPolicy);
    let many = vec![need("file:///x"); EGRESS_MAX_NEEDS + 1];
    assert_eq!(fulfilment.fulfil(&many), Err("egress_needs_too_many"));
    let round = vec![need("file:///x"); EGRESS_MAX_NEEDS];
    for _ in 0..(EGRESS_MAX_SUPPLIED / EGRESS_MAX_NEEDS) {
        fulfilment.fulfil(&round).expect("round");
    }
    assert_eq!(fulfilment.supplied().len(), EGRESS_MAX_SUPPLIED);
    assert_eq!(fulfilment.fulfil(&round), Err("egress_supplied_too_many"));
}

#[test]
fn a_location_resolves_against_the_current_url() {
    assert_eq!(
        redirect_target("https://a.example/one/two", "three"),
        Some("https://a.example/one/three".to_owned())
    );
    assert_eq!(
        redirect_target("https://a.example/one/two?q=1", "/four"),
        Some("https://a.example/four".to_owned())
    );
    assert_eq!(
        redirect_target("https://a.example/one", "https://b.example/five"),
        Some("https://b.example/five".to_owned())
    );
    // No downgrade, no other scheme, no header injection.
    assert_eq!(
        redirect_target("https://a.example/one", "http://a.example/x"),
        None
    );
    assert_eq!(
        redirect_target("https://a.example/one", "ftp://a.example/x"),
        None
    );
    assert_eq!(
        redirect_target("https://a.example/one", "/x\r\nHost: b"),
        None
    );
    assert_eq!(
        redirect_target("http://a.example/one", "https://a.example/x"),
        Some("https://a.example/x".to_owned())
    );
}

#[test]
fn a_managed_proxy_carries_the_stores_credentials_and_nothing_else() {
    let plain = managed_proxy("http://proxy.example:3128", None).expect("proxy");
    assert_eq!(plain.host(), "proxy.example");
    assert_eq!(plain.port(), 3128);
    assert_eq!(plain.username(), None);
    assert_eq!(plain.password(), None);

    let credentials = EgressProxyCredentials {
        username: "svc".to_owned(),
        password: "s3cret".to_owned(),
    };
    let authenticated =
        managed_proxy("https://proxy.example:8443", Some(&credentials)).expect("proxy");
    assert_eq!(authenticated.host(), "proxy.example");
    assert_eq!(authenticated.port(), 8443);
    assert_eq!(authenticated.username(), Some("svc"));
    assert_eq!(authenticated.password(), Some("s3cret"));

    // A bracketed IPv6 address keeps its brackets through the builder's own
    // `scheme://user:pass@host:port` round trip.
    let literal = managed_proxy("http://[::1]:3128", Some(&credentials)).expect("proxy");
    assert!(literal.host().contains("::1"), "{}", literal.host());
    assert_eq!(literal.port(), 3128);
    assert_eq!(literal.username(), Some("svc"));
}

#[test]
fn a_proxy_url_the_transport_cannot_express_is_no_proxy_at_all() {
    let credentials = EgressProxyCredentials {
        username: "svc".to_owned(),
        password: "s3cret".to_owned(),
    };
    for url in [
        // Only the two proxy protocols ureq speaks, always with an explicit port.
        "socks5://proxy.example:1080",
        "proxy.example:3128",
        "http://proxy.example",
    ] {
        assert!(managed_proxy(url, Some(&credentials)).is_none(), "{url}");
    }
}

#[test]
fn a_location_resolves_the_shapes_urljoin_accepts() {
    // Protocol-relative: the host changes, the scheme is kept.
    assert_eq!(
        redirect_target("https://a.example/one/two", "//cdn.example/pkg"),
        Some("https://cdn.example/pkg".to_owned())
    );
    // Query-only: the current path is kept.
    assert_eq!(
        redirect_target("https://a.example/one/two", "?page=2"),
        Some("https://a.example/one/two?page=2".to_owned())
    );
    // Dot segments are removed rather than sent.
    assert_eq!(
        redirect_target("https://a.example/one/two/three", "../four"),
        Some("https://a.example/one/four".to_owned())
    );
    assert_eq!(
        redirect_target("https://a.example/one/two", "./five"),
        Some("https://a.example/one/five".to_owned())
    );
    // A fragment belongs to the client, not the request.
    assert_eq!(
        redirect_target("https://a.example/one", "/six#anchor"),
        Some("https://a.example/six".to_owned())
    );
    assert_eq!(redirect_target("https://a.example/one", "   "), None);
}

#[test]
fn a_bespoke_header_stops_at_the_origin_it_was_addressed_to() {
    let spool = spool_dir("cross-origin");
    let (other, other_seen, _other_hits) = serve(vec![ok("{}")]);
    let (base, base_seen, _base_hits) = serve(vec![moved(&format!("{other}/moved"))]);
    let mut asked = need(&format!("{base}/start"));
    asked.max_redirects = 2;
    asked
        .headers
        .insert("X-Api-Key".to_owned(), "secret".to_owned());
    asked
        .headers
        .insert("Accept".to_owned(), "application/json".to_owned());
    let supplied = fulfil(&[asked.clone()], &spool);
    assert!(
        matches!(&supplied[0].outcome, EgressOutcomeV1::Response { status, .. } if *status == 200),
        "{:?}",
        supplied[0].outcome
    );
    let first = base_seen.lock().expect("lock")[0].to_ascii_lowercase();
    assert!(first.contains("x-api-key: secret"), "{first}");
    let hop = other_seen.lock().expect("lock")[0].to_ascii_lowercase();
    assert!(!hop.contains("x-api-key"), "{hop}");
    assert!(hop.contains("accept: application/json"), "{hop}");

    // The same hop inside the origin keeps every header.
    let (base, base_seen, _hits) = serve(vec![moved("/moved"), ok("{}")]);
    let mut asked = need(&format!("{base}/start"));
    asked.max_redirects = 2;
    asked
        .headers
        .insert("X-Api-Key".to_owned(), "secret".to_owned());
    let supplied = fulfil(&[asked], &spool);
    assert!(
        matches!(&supplied[0].outcome, EgressOutcomeV1::Response { status, .. } if *status == 200),
        "{:?}",
        supplied[0].outcome
    );
    let second = base_seen.lock().expect("lock")[1].to_ascii_lowercase();
    assert!(second.contains("x-api-key: secret"), "{second}");
}

#[test]
fn the_per_read_bound_is_never_widened() {
    assert_eq!(per_read_seconds(0.1), 0.1);
    assert_eq!(per_read_seconds(5.0), 5.0);
    assert_eq!(per_read_seconds(600.0), MAX_EXCHANGE_SECONDS);
    assert_eq!(per_read_seconds(0.0), MAX_EXCHANGE_SECONDS);
    assert_eq!(per_read_seconds(-1.0), MAX_EXCHANGE_SECONDS);
    assert_eq!(per_read_seconds(f64::NAN), MAX_EXCHANGE_SECONDS);
}

#[test]
fn a_caller_without_archives_refuses_every_truthy_descriptor() {
    let spool = spool_dir("claim");
    let mut fulfilment = EgressFulfilment::new(&spool, &UnmanagedEgressPolicy);

    // Absent, null and the empty containers claim nothing, exactly like
    // Python's `elif descriptors:` falling through.
    assert!(fulfilment.claim_archives(None).expect("absent").is_empty());
    assert!(fulfilment
        .claim_archives(Some(&serde_json::Value::Null))
        .expect("null")
        .is_empty());
    assert!(fulfilment
        .claim_archives(Some(&serde_json::json!([])))
        .expect("empty list")
        .is_empty());
    assert!(fulfilment
        .claim_archives(Some(&serde_json::json!({})))
        .expect("empty object")
        .is_empty());

    // A malformed container still names blobs this caller never held.
    for malformed in [
        serde_json::json!({"sha256": "a".repeat(64)}),
        serde_json::json!("sha256:deadbeef"),
        serde_json::json!(1),
        serde_json::json!([{"sha256": "b".repeat(64)}]),
    ] {
        assert_eq!(
            fulfilment.claim_archives(Some(&malformed)),
            Err(crate::egress_caller_archive::UNHELD_ARCHIVE),
            "{malformed}"
        );
    }
}
