//! Unit tests for the caller-brokered egress seam.

use super::*;

fn get(url: &str) -> GuardSyncRequest {
    GuardSyncRequest {
        url: url.to_owned(),
        method: "GET".to_owned(),
        headers: BTreeMap::new(),
        body: None,
        dpop_nonce: None,
        retry_context: None,
    }
}

fn post(url: &str, body: &[u8]) -> GuardSyncRequest {
    GuardSyncRequest {
        method: "POST".to_owned(),
        body: Some(body.to_vec()),
        ..get(url)
    }
}

fn ok_response(body: &str) -> EgressOutcomeV1 {
    EgressOutcomeV1::Response {
        status: 200,
        headers: BTreeMap::new(),
        body: Some(body.to_owned()),
        body_file: None,
    }
}

fn supplied(
    class: &str,
    request: &GuardSyncRequest,
    occurrence: u32,
    outcome: EgressOutcomeV1,
) -> EgressSuppliedV1 {
    EgressSuppliedV1 {
        class: class.to_owned(),
        method: request.method.clone(),
        url: request.url.clone(),
        body_sha256: body_digest(request.body.as_deref()),
        occurrence,
        outcome,
    }
}

const REGISTRY_URL: &str = "https://registry.npmjs.org/left-pad";

#[test]
fn unanswered_exchange_is_recorded_not_dialed() {
    let scope = EgressScope::enter(&[], None).unwrap();
    let result = exchange(EgressClass::Registry, &get(REGISTRY_URL), 1.0, 0, 1024);
    assert!(matches!(result, Err(SyncHttpError::Other(_))));
    assert!(needs_pending());
    let needs = scope.finish();
    assert_eq!(needs.len(), 1);
    assert_eq!(needs[0].class, "registry");
    assert_eq!(needs[0].url, REGISTRY_URL);
    assert_eq!(needs[0].occurrence, 1);
    assert!(!needs_pending());
}

#[test]
fn supplied_outcome_replays_and_later_exchange_becomes_the_next_need() {
    let first = get(REGISTRY_URL);
    let entries = [supplied("registry", &first, 1, ok_response("{\"a\":1}"))];
    let scope = EgressScope::enter(&entries, None).unwrap();
    let answered = exchange(EgressClass::Registry, &first, 1.0, 0, 1024).unwrap();
    assert_eq!(answered.body_bytes, b"{\"a\":1}");
    assert!(!needs_pending());
    // The same request again is a second occurrence with no answer yet.
    assert!(exchange(EgressClass::Registry, &first, 1.0, 0, 1024).is_err());
    let needs = scope.finish();
    assert_eq!(needs.len(), 1);
    assert_eq!(needs[0].occurrence, 2);
}

#[test]
fn non_success_status_keeps_lowercased_headers_for_retry_decisions() {
    let request = get(REGISTRY_URL);
    let outcome = EgressOutcomeV1::Response {
        status: 429,
        headers: BTreeMap::from([("Retry-After".to_owned(), "3".to_owned())]),
        body: None,
        body_file: None,
    };
    let _scope = EgressScope::enter(&[supplied("registry", &request, 1, outcome)], None).unwrap();
    match exchange(EgressClass::Registry, &request, 1.0, 0, 1024) {
        Err(SyncHttpError::Http {
            status, headers, ..
        }) => {
            assert_eq!(status, 429);
            assert_eq!(headers.get("retry-after").map(String::as_str), Some("3"));
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn retry_pause_is_carried_to_the_next_need_as_a_delay_hint() {
    let request = get(REGISTRY_URL);
    let gateway = EgressOutcomeV1::Response {
        status: 502,
        headers: BTreeMap::new(),
        body: None,
        body_file: None,
    };
    let scope = EgressScope::enter(&[supplied("registry", &request, 1, gateway)], None).unwrap();
    assert!(exchange(EgressClass::Registry, &request, 1.0, 0, 1024).is_err());
    pause(1.0);
    assert!(exchange(EgressClass::Registry, &request, 1.0, 0, 1024).is_err());
    let needs = scope.finish();
    assert_eq!(needs.len(), 1);
    assert_eq!(needs[0].occurrence, 2);
    assert!((needs[0].delay_seconds - 1.0).abs() < f64::EPSILON);
}

#[test]
fn only_registry_reads_are_collected_after_a_pending_need() {
    let scope = EgressScope::enter(&[], None).unwrap();
    let cloud = post("https://cloud.example/api", b"{}");
    assert!(exchange(EgressClass::Cloud, &cloud, 1.0, 0, 1024).is_err());
    assert!(exchange(EgressClass::Registry, &get(REGISTRY_URL), 1.0, 0, 1024).is_err());
    let oauth = post("https://cloud.example/oauth/token", b"x=1");
    assert!(exchange(EgressClass::Oauth, &oauth, 1.0, 0, 1024).is_err());
    assert!(matches!(
        exchange_archive("https://example.com/a.tgz", 10, 3, 5.0),
        ArchiveExchange::Unavailable(_)
    ));
    let classes: Vec<_> = scope.finish().into_iter().map(|n| n.class).collect();
    assert_eq!(classes, ["cloud", "registry"]);
}

#[test]
fn needs_are_capped_per_round() {
    let scope = EgressScope::enter(&[], None).unwrap();
    for index in 0..(EGRESS_MAX_NEEDS + 4) {
        let url = format!("https://registry.npmjs.org/p{index}");
        let _ = exchange(EgressClass::Registry, &get(&url), 1.0, 0, 1024);
    }
    assert_eq!(scope.finish().len(), EGRESS_MAX_NEEDS);
}

#[test]
fn deny_all_scope_never_records_a_need() {
    let scope = EgressScope::deny_all().unwrap();
    assert!(exchange(EgressClass::Registry, &get(REGISTRY_URL), 1.0, 0, 1024).is_err());
    assert!(matches!(
        exchange_archive("https://example.com/a.tgz", 10, 3, 5.0),
        ArchiveExchange::Unavailable(_)
    ));
    assert!(!needs_pending());
    assert!(scope.finish().is_empty());
}

#[test]
fn a_second_scope_is_refused() {
    let _scope = EgressScope::enter(&[], None).unwrap();
    assert!(EgressScope::deny_all().is_err());
}

#[test]
fn blocked_outcome_is_a_failure_and_never_a_response() {
    let request = get(REGISTRY_URL);
    let blocked = EgressOutcomeV1::Blocked {
        code: "public_registry_not_allowed".to_owned(),
    };
    let _scope = EgressScope::enter(&[supplied("registry", &request, 1, blocked)], None).unwrap();
    match exchange(EgressClass::Registry, &request, 1.0, 0, 1024) {
        Err(SyncHttpError::Other(message)) => {
            assert!(message.contains("public_registry_not_allowed"));
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn archive_outcomes_map_to_the_exchange_result() {
    let url = "https://example.com/a.tgz";
    let archive = |outcome| supplied_archive(url, outcome);
    let _scope = EgressScope::enter(
        &[archive(EgressOutcomeV1::Archive {
            sha256: "ab".repeat(32),
            size: 7,
            final_url: url.to_owned(),
            inspection: None,
        })],
        None,
    )
    .unwrap();
    assert_eq!(
        exchange_archive(url, 10, 3, 5.0),
        ArchiveExchange::Downloaded {
            sha256: "ab".repeat(32),
            size: 7,
            final_url: url.to_owned()
        }
    );
}

fn supplied_archive(url: &str, outcome: EgressOutcomeV1) -> EgressSuppliedV1 {
    supplied("archive", &get(url), 1, outcome)
}

#[test]
fn blocked_archive_is_a_failure() {
    let url = "https://example.com/a.tgz";
    let blocked = EgressOutcomeV1::Blocked {
        code: "destination_not_allowed".to_owned(),
    };
    let _scope = EgressScope::enter(&[supplied_archive(url, blocked)], None).unwrap();
    assert!(matches!(
        exchange_archive(url, 10, 3, 5.0),
        ArchiveExchange::Failed { code, .. } if code == "destination_not_allowed"
    ));
}

#[test]
fn malformed_supplied_entries_are_refused() {
    let request = get(REGISTRY_URL);
    let entry = supplied("registry", &request, 1, ok_response("{}"));
    let mut bad_class = entry.clone();
    bad_class.class = "other".to_owned();
    assert!(EgressScope::enter(&[bad_class], None).is_err());
    let mut zero = entry.clone();
    zero.occurrence = 0;
    assert!(EgressScope::enter(&[zero], None).is_err());
    assert!(EgressScope::enter(&[entry.clone(), entry.clone()], None).is_err());
    assert!(EgressScope::enter(&[], Some("relative/dir")).is_err());
}

#[test]
fn a_request_may_carry_more_than_sixty_four_replayed_outcomes() {
    let many = |count: usize| -> Vec<EgressSuppliedV1> {
        (0..count)
            .map(|index| {
                let request = get(&format!("https://registry.npmjs.org/package-{index}"));
                supplied("registry", &request, 1, ok_response("{}"))
            })
            .collect()
    };
    // A command with ~100 ranged packages replays 100 registry outcomes.
    let scope = EgressScope::enter(&many(100), None).expect("100 outcomes are within the cap");
    let request = get("https://registry.npmjs.org/package-99");
    assert!(exchange(EgressClass::Registry, &request, 1.0, 0, 1024).is_ok());
    drop(scope);
    assert!(EgressScope::enter(&many(EGRESS_MAX_SUPPLIED), None).is_ok());
    assert!(EgressScope::enter(&many(EGRESS_MAX_SUPPLIED + 1), None).is_err());
}

#[test]
fn inline_body_over_the_inline_or_response_cap_is_refused() {
    let request = get(REGISTRY_URL);
    let _scope = EgressScope::enter(
        &[supplied("registry", &request, 1, ok_response("0123456789"))],
        None,
    )
    .unwrap();
    assert!(matches!(
        exchange(EgressClass::Registry, &request, 1.0, 0, 4),
        Err(SyncHttpError::Other(message)) if message.contains("too large")
    ));
}

fn spool_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("egress-broker-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn file_response(name: &str) -> EgressOutcomeV1 {
    EgressOutcomeV1::Response {
        status: 200,
        headers: BTreeMap::new(),
        body: None,
        body_file: Some(name.to_owned()),
    }
}

#[test]
fn spool_file_is_read_within_the_cap_and_only_from_the_spool_dir() {
    let dir = spool_dir("read");
    std::fs::write(dir.join("body-1"), b"{\"big\":true}").unwrap();
    let request = get(REGISTRY_URL);
    let dir_text = dir.to_str().unwrap();
    {
        let _scope = EgressScope::enter(
            &[supplied("registry", &request, 1, file_response("body-1"))],
            Some(dir_text),
        )
        .unwrap();
        let answered = exchange(EgressClass::Registry, &request, 1.0, 0, 1024).unwrap();
        assert_eq!(answered.body_bytes, b"{\"big\":true}");
    }
    for bad in ["../body-1", "/etc/hosts", ".hidden", "a/b", ""] {
        let _scope = EgressScope::enter(
            &[supplied("registry", &request, 1, file_response(bad))],
            Some(dir_text),
        )
        .unwrap();
        assert!(
            exchange(EgressClass::Registry, &request, 1.0, 0, 1024).is_err(),
            "{bad:?} must be refused"
        );
    }
    {
        let _scope = EgressScope::enter(
            &[supplied("registry", &request, 1, file_response("body-1"))],
            Some(dir_text),
        )
        .unwrap();
        assert!(exchange(EgressClass::Registry, &request, 1.0, 0, 4).is_err());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn spool_symlink_is_not_followed() {
    let dir = spool_dir("link");
    std::fs::write(dir.join("real"), b"{}").unwrap();
    std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
    let request = get(REGISTRY_URL);
    let _scope = EgressScope::enter(
        &[supplied("registry", &request, 1, file_response("link"))],
        Some(dir.to_str().unwrap()),
    )
    .unwrap();
    assert!(exchange(EgressClass::Registry, &request, 1.0, 0, 1024).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn archive_need_asks_for_inspection_and_the_reported_verdict_is_kept() {
    let url = "https://example.com/a.tgz";
    let scope = EgressScope::enter(&[], None).unwrap();
    assert!(matches!(
        exchange_archive(url, 10, 3, 5.0),
        ArchiveExchange::Unavailable(_)
    ));
    let needs = scope.finish();
    let spec = needs[0].inspect.as_ref().expect("archive need inspects");
    assert_eq!(spec.max_files, 500);
    assert!(spec.timeout_seconds > 0.0);
    let verdict = ArchiveVerdictV1 {
        status: "clean".to_owned(),
        code: "ok".to_owned(),
        message: "clean".to_owned(),
        severity: "low".to_owned(),
    };
    let sha = "cd".repeat(32);
    let _scope = EgressScope::enter(
        &[supplied_archive(
            url,
            EgressOutcomeV1::Archive {
                sha256: sha.clone(),
                size: 7,
                final_url: url.to_owned(),
                inspection: Some(verdict.clone()),
            },
        )],
        None,
    )
    .unwrap();
    assert!(supplied_inspection(&sha).is_none());
    exchange_archive(url, 10, 3, 5.0);
    assert_eq!(supplied_inspection(&sha), Some(verdict));
}
