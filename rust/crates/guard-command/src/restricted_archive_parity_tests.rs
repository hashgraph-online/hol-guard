//! Expectations recorded from the pre-cutover Python implementation.

use super::*;
use serde_json::{json, Value};
use std::io::{Cursor, Read};
use std::sync::Mutex;

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../tests/fixtures/archive-acquisition-python.v1.json"
    ))
    .unwrap()
}

#[test]
fn recorded_destination_parity() {
    let _test_lock = crate::restricted_archive::ARCHIVE_TEST_LOCK.lock().unwrap();
    let mut mismatches = Vec::new();
    for case in vectors()["destinations"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let actual = match canonical_destination(input) {
            Ok(value) => json!({"url": value.url, "hostname": value.hostname,
                               "port": value.port, "request_target": value.request_target,
                               "host_header": value.host_header}),
            Err(error) => json!({"code": error.code, "message": error.message}),
        };
        if actual != case["expected"] {
            mismatches.push(format!("{input:?}: {actual} != {}", case["expected"]));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn recorded_public_address_parity() {
    let _test_lock = crate::restricted_archive::ARCHIVE_TEST_LOCK.lock().unwrap();
    let mut mismatches = Vec::new();
    for case in vectors()["addresses"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let actual = address_is_public(input.parse().unwrap());
        if actual != case["expected"].as_bool().unwrap() {
            mismatches.push(format!("{input}: {actual} != {}", case["expected"]));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn recorded_source_route_parity() {
    let _test_lock = crate::restricted_archive::ARCHIVE_TEST_LOCK.lock().unwrap();
    for case in vectors()["destinations"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        assert_eq!(
            is_external_https_archive_source(input),
            case["is_external"].as_bool().unwrap(),
            "{input:?}"
        );
    }
}

#[test]
fn same_scheme_redirects_inherit_authority() {
    let base = "https://packages.example.com/dir/archive.tgz";
    for (location, expected) in [
        (
            "https:next.tgz",
            "https://packages.example.com/dir/next.tgz",
        ),
        ("https:/next.tgz", "https://packages.example.com/next.tgz"),
        (
            "HTTPS:../next.tgz?signature=a%2Fb",
            "https://packages.example.com/next.tgz?signature=a%2Fb",
        ),
        ("https://other.example.com/a", "https://other.example.com/a"),
        ("http:next.tgz", "http:next.tgz"),
    ] {
        assert_eq!(super::urljoin(base, location), expected);
    }
}

struct Resolver(Vec<String>);
impl DnsResolver for Resolver {
    fn getaddrinfo(&self, _: &str) -> Result<Option<Vec<String>>, String> {
        Ok(Some(self.0.clone()))
    }
}

struct Response {
    status: u16,
    body: Cursor<Vec<u8>>,
    headers: Vec<(String, String)>,
}

impl ReadableResponse for Response {
    fn read(&mut self, amount: usize) -> Result<Vec<u8>, RestrictedDownloadError> {
        let mut bytes = vec![0; amount];
        let size = self.body.read(&mut bytes).unwrap();
        bytes.truncate(size);
        Ok(bytes)
    }
    fn get_header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }
    fn header_items(&self) -> Vec<(String, String)> {
        self.headers.clone()
    }
    fn set_timeout(&mut self, _: f64) {}
    fn close(&mut self) {}
    fn status(&self) -> u16 {
        self.status
    }
}

struct Transport {
    responses: Mutex<std::collections::VecDeque<Response>>,
    opened: Mutex<Vec<String>>,
}
impl PinnedHttpsTransport for Transport {
    fn open_pinned_https_response(
        &self,
        destination: &CanonicalDestination,
        _: &str,
        _: Instant,
    ) -> Result<Box<dyn ReadableResponse>, RestrictedDownloadError> {
        self.opened.lock().unwrap().push(destination.url.clone());
        Ok(Box::new(
            self.responses.lock().unwrap().pop_front().unwrap(),
        ))
    }
}

#[test]
fn recorded_download_parity() {
    let _test_lock = crate::restricted_archive::ARCHIVE_TEST_LOCK.lock().unwrap();
    let mut mismatches = Vec::new();
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).unwrap();
    let directory =
        std::env::temp_dir().join(format!("guard-acquisition-parity-{}", hex::encode(nonce)));
    std::fs::create_dir(&directory).unwrap();
    for case in vectors()["downloads"].as_array().unwrap() {
        let input = &case["input"];
        let responses = input["responses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| Response {
                status: item["status"].as_u64().unwrap() as u16,
                body: Cursor::new(item["body"].as_str().unwrap_or("").as_bytes().to_vec()),
                headers: item["headers"]
                    .as_object()
                    .map(|headers| {
                        headers
                            .iter()
                            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
            .collect();
        let transport = Transport {
            responses: Mutex::new(responses),
            opened: Mutex::new(Vec::new()),
        };
        let resolver = Resolver(
            input["addresses"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .map(|v| v.as_str().unwrap().to_owned())
                        .collect()
                })
                .unwrap_or_else(|| vec!["8.8.8.8".into()]),
        );
        let result = download_restricted_archive(
            input["url"]
                .as_str()
                .unwrap_or("https://packages.example.com/dir/archive.tgz"),
            input["max_bytes"].as_u64().unwrap_or(16),
            input["max_redirects"].as_u64().unwrap_or(4) as u32,
            1.0,
            Some(&directory),
            &resolver,
            &transport,
        );
        let actual = match result {
            RestrictedArchiveDownloadResult::Failure(error) => {
                json!({"kind": "failure", "code": error.code, "message": error.message})
            }
            RestrictedArchiveDownloadResult::Success(download) => {
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::metadata(&download.path)
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777
                };
                #[cfg(not(unix))]
                let mode = 0o400;
                let name = download.path.file_name().unwrap().to_str().unwrap();
                let suffix = if name.ends_with(".tar.gz") {
                    ".tar.gz"
                } else if name.ends_with(".tgz") {
                    ".tgz"
                } else if name.ends_with(".tar") {
                    ".tar"
                } else {
                    ".archive"
                };
                let actual = json!({"kind": "download", "sha256": download.sha256, "size": download.size,
                                    "final_url": download.final_url, "suffix": suffix, "mode": mode});
                download.cleanup();
                actual
            }
        };
        let opened = transport.opened.into_inner().unwrap();
        if actual != case["expected"] || json!(opened) != case["opened"] {
            mismatches.push(format!(
                "{}: {actual} != {}; opened {opened:?} != {}",
                case["name"], case["expected"], case["opened"]
            ));
        }
        assert_eq!(
            std::fs::read_dir(&directory).unwrap().count(),
            0,
            "blob leaked"
        );
    }
    std::fs::remove_dir(&directory).unwrap();
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}
