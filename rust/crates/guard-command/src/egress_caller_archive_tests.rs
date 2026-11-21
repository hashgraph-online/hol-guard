use super::*;
use std::cell::RefCell;
use std::time::Duration;

use serde_json::json;

use crate::egress_caller::{EgressFulfilment, EgressPolicy, UnmanagedEgressPolicy};
use crate::restricted_archive::RestrictedArchiveFailure;

const SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const BYTES: &[u8] = b"archive bytes";

/// Stages a blob where the fulfilment asked for it and records the call.
struct Downloads {
    /// Where a blob that must outlive the scratch directory is staged.
    home: PathBuf,
    /// `(url, timeout, a scratch directory was given)` per call.
    calls: RefCell<Vec<(String, f64, bool)>>,
    paths: RefCell<Vec<PathBuf>>,
    failure: Option<&'static str>,
    sleep: f64,
}

impl Downloads {
    fn new(tag: &str) -> Self {
        Self {
            home: scratch(&format!("{tag}-home")),
            calls: RefCell::new(Vec::new()),
            paths: RefCell::new(Vec::new()),
            failure: None,
            sleep: 0.0,
        }
    }

    fn calls(&self) -> Vec<(String, f64, bool)> {
        self.calls.borrow().clone()
    }

    fn path(&self, index: usize) -> PathBuf {
        self.paths.borrow()[index].clone()
    }
}

impl ArchiveDownloadApi for Downloads {
    fn download(
        &self,
        url: &str,
        _max_bytes: u64,
        _max_redirects: u32,
        timeout_seconds: f64,
        temp_dir: Option<&Path>,
    ) -> RestrictedArchiveDownloadResult {
        self.calls
            .borrow_mut()
            .push((url.to_owned(), timeout_seconds, temp_dir.is_some()));
        if self.sleep > 0.0 {
            std::thread::sleep(Duration::from_secs_f64(self.sleep));
        }
        if let Some(code) = self.failure {
            return RestrictedArchiveDownloadResult::Failure(RestrictedArchiveFailure {
                code: code.to_owned(),
                message: "refused".to_owned(),
            });
        }
        let index = self.calls.borrow().len();
        let path = temp_dir.unwrap_or(&self.home).join(format!("blob-{index}"));
        std::fs::write(&path, BYTES).expect("stage blob");
        self.paths.borrow_mut().push(path.clone());
        RestrictedArchiveDownloadResult::Success(RestrictedArchiveDownload {
            path,
            sha256: format!("{index}{}", &SHA[1..]),
            size: BYTES.len() as u64,
            source_url: url.to_owned(),
            final_url: format!("{url}?cdn=1"),
        })
    }
}

struct Inspections {
    status: &'static str,
    timeouts: RefCell<Vec<f64>>,
}

impl Inspections {
    fn new(status: &'static str) -> Self {
        Self {
            status,
            timeouts: RefCell::new(Vec::new()),
        }
    }
}

impl ArchiveInspectApi for Inspections {
    fn inspect(
        &self,
        _path: &Path,
        _expected_sha256: &str,
        timeout_seconds: f64,
        _max_archive_bytes: u64,
        _max_files: u64,
        _max_package_json_bytes: u64,
    ) -> ArchiveInspectionResult {
        self.timeouts.borrow_mut().push(timeout_seconds);
        ArchiveInspectionResult {
            status: self.status.to_owned(),
            code: format!("external_archive_inspection_{}", self.status),
            message: "inspected".to_owned(),
            severity: "low".to_owned(),
            sha256: None,
        }
    }
}

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("egress-archive-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("scratch dir");
    path
}

fn need(url: &str, inspect: Option<ArchiveInspectionSpecV1>) -> EgressNeedV1 {
    EgressNeedV1 {
        class: "archive".to_owned(),
        method: "GET".to_owned(),
        url: url.to_owned(),
        headers: Default::default(),
        body: None,
        body_sha256: String::new(),
        occurrence: 1,
        timeout_seconds: 30.0,
        max_redirects: 2,
        max_response_bytes: 64 * 1024 * 1024,
        delay_seconds: 0.0,
        inspect,
    }
}

fn spec(aggregate: f64) -> ArchiveInspectionSpecV1 {
    ArchiveInspectionSpecV1 {
        timeout_seconds: 30.0,
        aggregate_timeout_seconds: aggregate,
        max_files: 4096,
        max_package_json_bytes: 256 * 1024,
    }
}

#[test]
fn a_clean_archive_is_retained_and_claimed_by_its_descriptor() {
    let downloads = Downloads::new("claim");
    let inspections = Inspections::new("clean");
    let mut fulfilment = ArchiveFulfilment::new(&scratch("claim"), true, &downloads, &inspections);
    let outcome = fulfilment.fulfil(&need("https://registry.example/pkg.tgz", Some(spec(30.0))));
    let EgressOutcomeV1::Archive {
        sha256,
        size,
        final_url,
        inspection,
    } = &outcome
    else {
        panic!("{outcome:?}");
    };
    assert_eq!(size, &(BYTES.len() as u64));
    assert_eq!(final_url, "https://registry.example/pkg.tgz?cdn=1");
    assert_eq!(inspection.as_ref().expect("verdict").status, "clean");
    // Retained: staged outside the request's scratch directory and still there.
    assert!(!downloads.calls()[0].2);
    let blob = downloads.path(0);
    assert!(blob.is_file());

    let claimed = fulfilment
        .claim(&json!([{
            "sha256": sha256,
            "size": size,
            "source_url_hash": stable_digest_hex(b"https://registry.example/pkg.tgz"),
            "final_url_hash": stable_digest_hex(b"https://registry.example/pkg.tgz?cdn=1"),
        }]))
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].path, blob);
    assert!(blob.is_file());
}

#[test]
fn a_verdict_that_is_not_clean_keeps_no_blob() {
    let downloads = Downloads::new("blocked");
    let inspections = Inspections::new("blocked");
    let mut fulfilment =
        ArchiveFulfilment::new(&scratch("blocked"), true, &downloads, &inspections);
    let outcome = fulfilment.fulfil(&need("https://registry.example/bad.tgz", Some(spec(30.0))));
    let EgressOutcomeV1::Archive { inspection, .. } = &outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(inspection.as_ref().expect("verdict").status, "blocked");
    assert!(!downloads.path(0).exists());
    assert!(fulfilment.claim(&json!([])).expect("claim").is_empty());
}

#[test]
fn an_unheld_descriptor_fails_the_claim_and_removes_every_blob() {
    let downloads = Downloads::new("unheld");
    let inspections = Inspections::new("clean");
    let mut fulfilment = ArchiveFulfilment::new(&scratch("unheld"), true, &downloads, &inspections);
    let first = fulfilment.fulfil(&need("https://registry.example/one.tgz", Some(spec(30.0))));
    fulfilment.fulfil(&need("https://registry.example/two.tgz", Some(spec(30.0))));
    let EgressOutcomeV1::Archive { sha256, size, .. } = &first else {
        panic!("{first:?}");
    };
    let claim = fulfilment.claim(&json!([
        {
            "sha256": sha256,
            "size": size,
            "source_url_hash": stable_digest_hex(b"https://registry.example/one.tgz"),
            "final_url_hash": stable_digest_hex(b"https://registry.example/one.tgz?cdn=1"),
        },
        // The resident named a blob nobody downloaded.
        {"sha256": SHA, "size": 1, "source_url_hash": "x", "final_url_hash": "y"},
    ]));
    assert_eq!(claim, Err(UNHELD_ARCHIVE));
    assert!(!downloads.path(0).exists());
    assert!(!downloads.path(1).exists());
}

#[test]
fn a_fulfilment_nobody_claimed_leaves_no_blob() {
    let downloads = Downloads::new("drop");
    let inspections = Inspections::new("clean");
    {
        let mut fulfilment =
            ArchiveFulfilment::new(&scratch("drop"), true, &downloads, &inspections);
        fulfilment.fulfil(&need("https://registry.example/pkg.tgz", Some(spec(30.0))));
        assert!(downloads.path(0).is_file());
    }
    assert!(!downloads.path(0).exists());
}

#[test]
fn the_aggregate_timeout_covers_every_archive_of_one_request() {
    let mut downloads = Downloads::new("aggregate");
    downloads.sleep = 0.4;
    let inspections = Inspections::new("clean");
    let mut fulfilment =
        ArchiveFulfilment::new(&scratch("aggregate"), false, &downloads, &inspections);
    // 0.3 s for the whole request; the first download alone spends more.
    let first = fulfilment.fulfil(&need("https://registry.example/one.tgz", Some(spec(0.3))));
    assert!(
        matches!(first, EgressOutcomeV1::ArchiveFailure { ref code, .. } if code == TIMEOUT_CODE),
        "{first:?}"
    );
    let second = fulfilment.fulfil(&need("https://registry.example/two.tgz", Some(spec(0.3))));
    assert!(
        matches!(second, EgressOutcomeV1::ArchiveFailure { ref code, .. } if code == TIMEOUT_CODE),
        "{second:?}"
    );
    // The second need never reached the network.
    assert_eq!(downloads.calls().len(), 1);
}

#[test]
fn the_inspection_keeps_the_termination_grace_back() {
    let mut downloads = Downloads::new("grace");
    downloads.sleep = 0.2;
    let inspections = Inspections::new("clean");
    let mut fulfilment = ArchiveFulfilment::new(&scratch("grace"), true, &downloads, &inspections);
    // 0.6 s aggregate, 0.2 s spent downloading, 0.5 s grace: nothing is left.
    let outcome = fulfilment.fulfil(&need("https://registry.example/pkg.tgz", Some(spec(0.6))));
    assert!(
        matches!(outcome, EgressOutcomeV1::ArchiveFailure { ref code, .. } if code == TIMEOUT_CODE),
        "{outcome:?}"
    );
    assert!(inspections.timeouts.borrow().is_empty());
    assert!(!downloads.path(0).exists());
}

#[test]
fn both_timeouts_are_clamped_to_what_the_aggregate_leaves() {
    let downloads = Downloads::new("clamp");
    let inspections = Inspections::new("clean");
    let mut fulfilment = ArchiveFulfilment::new(&scratch("clamp"), true, &downloads, &inspections);
    // The need asks for 30 s each; the aggregate allows 5 s for both.
    fulfilment.fulfil(&need("https://registry.example/pkg.tgz", Some(spec(5.0))));
    let download_timeout = downloads.calls()[0].1;
    assert!(
        download_timeout > 4.0 && download_timeout <= 5.0,
        "{download_timeout}"
    );
    let inspect_timeout = inspections.timeouts.borrow()[0];
    assert!(
        inspect_timeout > 4.0 && inspect_timeout <= 5.0 - INSPECTION_GRACE_SECONDS,
        "{inspect_timeout}"
    );
}

#[test]
fn a_refused_download_reports_its_own_code() {
    let mut downloads = Downloads::new("refused");
    downloads.failure = Some("external_archive_network_not_authorized");
    let inspections = Inspections::new("clean");
    let mut fulfilment =
        ArchiveFulfilment::new(&scratch("refused"), true, &downloads, &inspections);
    let outcome = fulfilment.fulfil(&need("https://registry.example/pkg.tgz", Some(spec(30.0))));
    assert_eq!(
        outcome,
        EgressOutcomeV1::ArchiveFailure {
            code: "external_archive_network_not_authorized".to_owned(),
            message: "refused".to_owned(),
        }
    );
    assert!(inspections.timeouts.borrow().is_empty());
}

#[test]
fn an_uninspected_archive_reports_no_verdict_and_leaves_the_scratch_empty() {
    let downloads = Downloads::new("bare");
    let inspections = Inspections::new("clean");
    let scratch_dir = scratch("bare");
    let outcome = {
        let mut fulfilment = ArchiveFulfilment::new(&scratch_dir, false, &downloads, &inspections);
        fulfilment.fulfil(&need("https://registry.example/pkg.tgz", None))
    };
    let EgressOutcomeV1::Archive { inspection, .. } = &outcome else {
        panic!("{outcome:?}");
    };
    assert!(inspection.is_none());
    assert!(inspections.timeouts.borrow().is_empty());
    // No aggregate timeout to clamp against: the need's own timeout stands.
    assert_eq!(downloads.calls()[0].1, 30.0);
    // Without retain the blob is staged in the request's scratch directory,
    // which is gone with the blob inside it.
    assert!(downloads.calls()[0].2);
    assert!(!downloads.path(0).exists());
    assert_eq!(std::fs::read_dir(&scratch_dir).expect("scratch").count(), 0);
}

#[test]
fn a_destination_the_policy_refuses_is_never_downloaded() {
    struct Refusing;
    impl EgressPolicy for Refusing {
        fn validate(&self, _url: &str) -> Result<(), String> {
            Err("managed_public_registry_disabled".to_owned())
        }
    }
    let downloads = Downloads::new("policy-refused");
    let inspections = Inspections::new("clean");
    let mut archives =
        ArchiveFulfilment::new(&scratch("policy-refused"), false, &downloads, &inspections);
    let spool = scratch("policy-refused-spool");
    let mut caller = EgressFulfilment::with_archives(&spool, &Refusing, &mut archives);
    caller
        .fulfil(&[need("https://registry.npmjs.org/pkg.tgz", Some(spec(30.0)))])
        .expect("fulfil");
    assert!(
        matches!(&caller.supplied()[0].outcome, EgressOutcomeV1::ArchiveFailure { code, .. }
            if code == "managed_public_registry_disabled"),
        "{:?}",
        caller.supplied()[0].outcome
    );
    // The refusal lands before acquisition, so nothing was fetched.
    assert!(downloads.calls().is_empty());

    // The same policy bound to the transport refuses the destination before DNS,
    // so a caller that does reach acquisition cannot route around it.
    struct NeverOpens;
    impl PinnedHttpsTransport for NeverOpens {
        fn open_pinned_https_response(
            &self,
            _destination: &CanonicalDestination,
            _address: &str,
            _deadline: std::time::Instant,
        ) -> Result<Box<dyn ReadableResponse>, RestrictedDownloadError> {
            panic!("a refused destination must never be opened");
        }
    }
    let bound = PolicyBoundTransport {
        inner: &NeverOpens,
        policy: &Refusing,
    };
    let refused = bound
        .validate_destination(&CanonicalDestination {
            url: "https://registry.npmjs.org/pkg.tgz".to_owned(),
            hostname: "registry.npmjs.org".to_owned(),
            port: 443,
            request_target: "/pkg.tgz".to_owned(),
            host_header: "registry.npmjs.org".to_owned(),
        })
        .expect_err("refused");
    assert_eq!(refused.code, "managed_public_registry_disabled");
}

#[test]
fn an_archive_need_reaches_the_fulfilment_through_the_caller() {
    let downloads = Downloads::new("wired");
    let inspections = Inspections::new("clean");
    let mut archives = ArchiveFulfilment::new(&scratch("wired"), false, &downloads, &inspections);
    let spool = scratch("wired-spool");
    let mut caller = EgressFulfilment::with_archives(&spool, &UnmanagedEgressPolicy, &mut archives);
    caller
        .fulfil(&[need("https://registry.example/pkg.tgz", Some(spec(30.0)))])
        .expect("fulfil");
    let supplied = caller.supplied();
    assert_eq!(supplied.len(), 1);
    assert_eq!(supplied[0].class, "archive");
    assert!(
        matches!(&supplied[0].outcome, EgressOutcomeV1::Archive { inspection, .. }
            if inspection.as_ref().expect("verdict").status == "clean"),
        "{:?}",
        supplied[0].outcome
    );
}
