//! Unauthenticated public-registry metadata GET for package range resolution.
//!
//! Mirrors the plain-request path of `runner.py:_urlopen_json_with_timeout_retry`
//! as `supply_chain_package_services._npm_registry_resolved_version` and
//! `_pypi_registry_resolved_version` drive it: a 1 second budget, a bounded
//! gateway retry with a 1 second pause, and every other failure (timeout, 429,
//! other HTTP status, transport error, undecodable or non-object body) read as
//! "unresolved". A request without DPoP material has no re-signing context, so
//! Python re-raises a timeout or a 429 instead of retrying; this does the same.
//! A 429 does not sleep first (Python sleeps up to 120 seconds before
//! re-raising) because a resident request must not stall on a public registry.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{Map, Value};

use crate::guard_sync_transport::{
    execute_request_following, status_is_retryable_gateway, SyncHttpError,
};
use crate::supply_chain_package_eval::GuardSyncRequest;

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

/// GET one registry metadata document and return its top-level JSON object.
pub fn fetch_registry_metadata(url: &str, accept: &str) -> Option<Map<String, Value>> {
    fetch_registry_metadata_with_pause(url, accept, REGISTRY_GATEWAY_PAUSE)
}

fn fetch_registry_metadata_with_pause(
    url: &str,
    accept: &str,
    gateway_pause: Duration,
) -> Option<Map<String, Value>> {
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
        match execute_request_following(&request, REGISTRY_TIMEOUT_SECONDS, REGISTRY_REDIRECT_LIMIT)
        {
            Ok(response) => {
                return match serde_json::from_slice::<Value>(&response.body_bytes) {
                    Ok(Value::Object(payload)) => Some(payload),
                    _ => None,
                };
            }
            Err(SyncHttpError::Http { status, .. })
                if status_is_retryable_gateway(status)
                    && gateway_retries < REGISTRY_GATEWAY_RETRY_LIMIT =>
            {
                gateway_retries += 1;
                std::thread::sleep(gateway_pause);
            }
            Err(_) => return None,
        }
    }
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
        assert!(payload.get("versions").is_some());
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
    fn unreachable_host_is_unresolved() {
        assert!(fetch_registry_metadata("http://127.0.0.1:1/p", "application/json").is_none());
    }
}
