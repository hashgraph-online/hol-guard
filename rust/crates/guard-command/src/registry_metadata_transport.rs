//! Public-registry metadata GET for package range resolution.
//!
//! Mirrors the plain-request path of `runner.py:_urlopen_json_with_timeout_retry`
//! as `supply_chain_package_services._npm_registry_resolved_version` and
//! `_pypi_registry_resolved_version` drive it: a 1 second budget, a bounded
//! gateway retry with a 1 second pause, and every other failure (timeout, 429,
//! other HTTP status, transport error, undecodable or non-object body) read as
//! "unresolved". A request without DPoP material has no re-signing context, so
//! Python re-raises a timeout or a 429 instead of retrying; this does the same.
//! Python sleeps up to two minutes before re-raising a 429, which only delays
//! the same unresolved answer, so the 429 is answered immediately here.
//!
//! The GET itself is performed by the caller that owns the managed network
//! policy (see `egress_broker`); this module parses and decides.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;

use crate::egress_broker::{self, EgressClass};
use crate::guard_sync_transport::{status_is_retryable_gateway, SyncHttpError};
use crate::supply_chain_package_eval::{GuardSyncRequest, RegistryDocument};

/// `supply_chain_package_services._TIMEOUT_SECONDS`.
const REGISTRY_TIMEOUT_SECONDS: f64 = 1.0;
/// `_SYNC_RETRYABLE_GATEWAY_MAX_ATTEMPTS`.
const REGISTRY_GATEWAY_RETRY_LIMIT: u32 = 2;
/// `_retry_after_sleep_seconds` is `min(max(1, Retry-After), retry_timeout)`
/// and `_RETRY_TIMEOUT_SECONDS` is 1, so the pause is always one second.
const REGISTRY_GATEWAY_PAUSE: Duration = Duration::from_secs(1);
/// `urllib.request`'s `HTTPRedirectHandler.max_redirections`.
const REGISTRY_REDIRECT_LIMIT: u32 = 10;
/// `supply_chain_package_services` request header.
const REGISTRY_USER_AGENT: &str = "hol-guard-local";
/// Registry metadata body cap, chosen from the public registries rather than
/// inherited from a library default. The largest abbreviated npm document
/// measured in practice is `next` at about 25.6 MB (`typescript` is about
/// 8.7 MB and `lodash` about 0.4 MB), and a PyPI JSON document for a package
/// with thousands of releases is a few MB. 32 MiB leaves headroom over the
/// largest measured document, while a body beyond it is hostile or broken and
/// is read as unresolved. The 10 MiB `ureq` default would have refused
/// `next` outright.
pub const REGISTRY_MAX_BODY_BYTES: u64 = 32 * 1024 * 1024;

/// GET one registry metadata document and return its top-level JSON object
/// with the `versions` keys in document order.
pub fn fetch_registry_metadata(url: &str, accept: &str) -> Option<RegistryDocument> {
    fetch_registry_metadata_with_pause(url, accept, REGISTRY_GATEWAY_PAUSE)
}

fn fetch_registry_metadata_with_pause(
    url: &str,
    accept: &str,
    gateway_pause: Duration,
) -> Option<RegistryDocument> {
    let mut headers = BTreeMap::new();
    headers.insert("Accept".to_owned(), accept.to_owned());
    headers.insert("User-Agent".to_owned(), REGISTRY_USER_AGENT.to_owned());
    let request = GuardSyncRequest {
        url: url.to_owned(),
        method: "GET".to_owned(),
        headers,
        body: None,
        dpop_nonce: None,
        retry_context: None,
    };
    let mut gateway_retries: u32 = 0;
    loop {
        match egress_broker::exchange(
            EgressClass::Registry,
            &request,
            REGISTRY_TIMEOUT_SECONDS,
            REGISTRY_REDIRECT_LIMIT,
            REGISTRY_MAX_BODY_BYTES,
        ) {
            Ok(response) => return parse_registry_document(&response.body_bytes),
            Err(SyncHttpError::Http { status, .. })
                if status_is_retryable_gateway(status)
                    && gateway_retries < REGISTRY_GATEWAY_RETRY_LIMIT =>
            {
                gateway_retries += 1;
                egress_broker::pause(gateway_pause.as_secs_f64());
            }
            Err(_) => return None,
        }
    }
}

/// The top-level object of a registry body, or `None` for anything else.
pub fn parse_registry_document(body: &[u8]) -> Option<RegistryDocument> {
    let Value::Object(object) = serde_json::from_slice::<Value>(body).ok()? else {
        return None;
    };
    Some(RegistryDocument {
        version_order: ordered_versions(body),
        object,
    })
}

/// The keys of the top-level `versions` object in the order they appear in
/// the document. `serde_json::Map` sorts keys, and Python iterates a `dict` in
/// insertion order, so a tie between equally ranked versions resolves to the
/// earlier key only if that order survives. The `preserve_order` feature would
/// reorder every map in the process, so the order is read here, from this one
/// field, instead.
fn ordered_versions(body: &[u8]) -> Vec<String> {
    #[derive(Deserialize)]
    struct Document {
        #[serde(default, deserialize_with = "object_keys")]
        versions: Vec<String>,
    }
    serde_json::from_slice::<Document>(body)
        .map(|document| document.versions)
        .unwrap_or_default()
}

fn object_keys<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    struct Keys;
    impl<'de> Visitor<'de> for Keys {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("any JSON value")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut seen = std::collections::HashSet::new();
            let mut keys = Vec::new();
            while let Some(key) = map.next_key::<String>()? {
                map.next_value::<IgnoredAny>()?;
                // A repeated key keeps its first position, as a Python dict does.
                if seen.insert(key.clone()) {
                    keys.push(key);
                }
            }
            Ok(keys)
        }
        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }
        fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }
        fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }
        fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }
        fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }
        fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok(Vec::new())
        }
    }
    deserializer.deserialize_any(Keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// Serve `responses` in order on loopback; returns the base URL, the raw
    /// requests seen, and a hit counter.
    fn serve(
        responses: Vec<String>,
    ) -> (String, Arc<AtomicU32>, Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let hits = Arc::new(AtomicU32::new(0));
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (hits_thread, seen_thread) = (hits.clone(), seen.clone());
        std::thread::spawn(move || {
            for response in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                seen_thread
                    .lock()
                    .expect("lock")
                    .push(String::from_utf8_lossy(&buf[..n]).into_owned());
                hits_thread.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (base, hits, seen)
    }

    fn ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn status(code: u16) -> String {
        format!("HTTP/1.1 {code} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    }

    #[test]
    fn returns_object_and_sends_python_headers() {
        let (base, _, seen) = serve(vec![ok(r#"{"versions":{"1.0.0":{}}}"#)]);
        let payload = fetch_registry_metadata(&format!("{base}/pkg"), "application/json")
            .expect("object payload");
        assert!(payload.object.get("versions").is_some());
        let request = seen.lock().expect("lock")[0].to_lowercase();
        assert!(request.contains("accept: application/json"));
        assert!(request.contains("user-agent: hol-guard-local"));
    }

    #[test]
    fn non_object_and_undecodable_bodies_are_unresolved() {
        for body in ["[1,2]", "not json", "\"str\"", "null"] {
            let (base, _, _) = serve(vec![ok(body)]);
            assert!(fetch_registry_metadata(&format!("{base}/p"), "application/json").is_none());
        }
    }

    #[test]
    fn gateway_status_retries_twice_then_succeeds() {
        let (base, hits, _) = serve(vec![status(503), status(502), ok("{}")]);
        let payload = fetch_registry_metadata_with_pause(
            &format!("{base}/p"),
            "application/json",
            Duration::from_millis(1),
        );
        assert!(payload.is_some());
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn gateway_status_gives_up_after_two_retries() {
        let (base, hits, _) = serve(vec![status(503), status(503), status(503), ok("{}")]);
        let payload = fetch_registry_metadata_with_pause(
            &format!("{base}/p"),
            "application/json",
            Duration::from_millis(1),
        );
        assert!(payload.is_none());
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn rate_limit_and_client_errors_do_not_retry() {
        for code in [429u16, 404, 500] {
            let (base, hits, _) = serve(vec![status(code), ok("{}")]);
            assert!(fetch_registry_metadata(&format!("{base}/p"), "application/json").is_none());
            assert_eq!(hits.load(Ordering::SeqCst), 1, "status {code}");
        }
    }

    #[test]
    fn versions_keep_document_order_not_sorted_order() {
        let document = parse_registry_document(
            br#"{"name":"p","versions":{"2.0.0":{},"1.0.0":{},"1.5.0":{"versions":{"z":1}}},"time":{}}"#,
        )
        .expect("document");
        assert_eq!(document.version_order, ["2.0.0", "1.0.0", "1.5.0"]);
        // Only the top-level `versions` field counts, wherever it appears.
        let nested = parse_registry_document(
            br#"{"dist-tags":{"versions":{"x":1}},"versions":{"b":{},"a":{}}}"#,
        )
        .expect("document");
        assert_eq!(nested.version_order, ["b", "a"]);
        let missing = parse_registry_document(br#"{"name":"p"}"#).expect("document");
        assert!(missing.version_order.is_empty());
    }

    #[test]
    fn a_realistic_large_document_is_accepted_under_the_cap() {
        // Roughly the size of the largest measured npm document (`next`).
        let entry = format!("{{\"description\":\"{}\"}}", "x".repeat(2000));
        let mut body = String::from("{\"versions\":{");
        for index in 0..12_000 {
            if index > 0 {
                body.push(',');
            }
            body.push_str(&format!("\"1.0.{index}\":{entry}"));
        }
        body.push_str("}}");
        assert!(body.len() as u64 > 20 * 1024 * 1024);
        assert!((body.len() as u64) < REGISTRY_MAX_BODY_BYTES);
        let document = parse_registry_document(body.as_bytes()).expect("document");
        assert_eq!(document.version_order.len(), 12_000);
        assert_eq!(document.version_order[11_999], "1.0.11999");
    }

    fn registry_outcome(status: u16, body: &str) -> guard_contracts::EgressOutcomeV1 {
        guard_contracts::EgressOutcomeV1::Response {
            status,
            headers: BTreeMap::new(),
            body: Some(body.to_owned()),
            body_file: None,
        }
    }

    fn registry_need_key(url: &str) -> (String, String, String) {
        ("GET".to_owned(), url.to_owned(), String::new())
    }

    fn supplied_registry(
        url: &str,
        occurrence: u32,
        outcome: guard_contracts::EgressOutcomeV1,
    ) -> guard_contracts::EgressSuppliedV1 {
        let (method, url, body_sha256) = registry_need_key(url);
        guard_contracts::EgressSuppliedV1 {
            class: "registry".to_owned(),
            method,
            url,
            body_sha256,
            occurrence,
            outcome,
        }
    }

    #[test]
    fn brokered_fetch_asks_the_caller_and_never_dials_the_registry() {
        let url = "https://registry.npmjs.org/left-pad";
        let scope = egress_broker::EgressScope::enter(&[], None).expect("scope");
        assert!(fetch_registry_metadata(url, "application/json").is_none());
        let needs = scope.finish();
        assert_eq!(needs.len(), 1);
        assert_eq!(needs[0].url, url);
        assert_eq!(needs[0].max_response_bytes, REGISTRY_MAX_BODY_BYTES);
        assert_eq!(needs[0].max_redirects, REGISTRY_REDIRECT_LIMIT);
        assert_eq!(
            needs[0].headers.get("Accept").map(String::as_str),
            Some("application/json")
        );
    }

    #[test]
    fn caller_refusal_by_managed_policy_leaves_the_package_unresolved() {
        for host in [
            "https://registry.npmjs.org/left-pad",
            "https://pypi.org/pypi/x/json",
        ] {
            let blocked = guard_contracts::EgressOutcomeV1::Blocked {
                code: "public_registry_not_allowed".to_owned(),
            };
            let scope =
                egress_broker::EgressScope::enter(&[supplied_registry(host, 1, blocked)], None)
                    .expect("scope");
            assert!(fetch_registry_metadata(host, "application/json").is_none());
            assert!(scope.finish().is_empty(), "a refusal is final, not retried");
        }
    }

    #[test]
    fn brokered_rate_limit_is_unresolved_without_a_retry_need() {
        let url = "https://registry.npmjs.org/left-pad";
        let scope = egress_broker::EgressScope::enter(
            &[supplied_registry(url, 1, registry_outcome(429, ""))],
            None,
        )
        .expect("scope");
        assert!(fetch_registry_metadata(url, "application/json").is_none());
        assert!(scope.finish().is_empty());
    }

    #[test]
    fn brokered_gateway_retry_replays_with_a_delay_hint() {
        let url = "https://registry.npmjs.org/left-pad";
        let scope = egress_broker::EgressScope::enter(
            &[supplied_registry(url, 1, registry_outcome(503, ""))],
            None,
        )
        .expect("scope");
        assert!(fetch_registry_metadata(url, "application/json").is_none());
        let needs = scope.finish();
        assert_eq!(needs.len(), 1);
        assert_eq!(needs[0].occurrence, 2);
        assert!(needs[0].delay_seconds > 0.0);
    }

    #[test]
    fn brokered_success_parses_the_supplied_body() {
        let url = "https://registry.npmjs.org/left-pad";
        let scope = egress_broker::EgressScope::enter(
            &[supplied_registry(
                url,
                1,
                registry_outcome(200, r#"{"versions":{"2.0.0":{},"1.0.0":{}}}"#),
            )],
            None,
        )
        .expect("scope");
        let document = fetch_registry_metadata(url, "application/json").expect("document");
        assert_eq!(document.version_order, ["2.0.0", "1.0.0"]);
        assert!(scope.finish().is_empty());
    }

    #[test]
    fn unreachable_host_is_unresolved() {
        assert!(fetch_registry_metadata("http://127.0.0.1:1/p", "application/json").is_none());
    }
}
