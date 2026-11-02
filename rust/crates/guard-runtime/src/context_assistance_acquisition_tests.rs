use super::*;
use guard_command::restricted_archive::{
    CanonicalDestination, DnsResolver, PinnedHttpsTransport, ReadableResponse,
    RestrictedDownloadError,
};
use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicUsize, Mutex};
use std::time::{Duration, Instant};

struct Response {
    status: u16,
    bytes: VecDeque<u8>,
    location: Option<String>,
}
impl ReadableResponse for Response {
    fn read(&mut self, amount: usize) -> Result<Vec<u8>, RestrictedDownloadError> {
        Ok((0..amount.min(self.bytes.len()))
            .filter_map(|_| self.bytes.pop_front())
            .collect())
    }
    fn get_header(&self, name: &str) -> Option<String> {
        (name.eq_ignore_ascii_case("location"))
            .then(|| self.location.clone())
            .flatten()
    }
    fn header_items(&self) -> Vec<(String, String)> {
        self.location
            .iter()
            .map(|v| ("Location".into(), v.clone()))
            .collect()
    }
    fn set_timeout(&mut self, _: f64) {}
    fn close(&mut self) {}
    fn status(&self) -> u16 {
        self.status
    }
}
struct Mock {
    pending: Mutex<VecDeque<Response>>,
    opens: AtomicUsize,
    resolutions: AtomicUsize,
    source: String,
}
impl Mock {
    fn new(bytes: &[u8]) -> Self {
        Self {
            pending: Mutex::new(VecDeque::from([Response {
                status: 200,
                bytes: bytes.iter().copied().collect(),
                location: None,
            }])),
            opens: AtomicUsize::new(0),
            resolutions: AtomicUsize::new(0),
            source: URL.into(),
        }
    }
}
impl DnsResolver for Mock {
    fn getaddrinfo(&self, _: &str) -> Result<Option<Vec<String>>, String> {
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        Ok(Some(vec!["93.184.216.34".into()]))
    }
}
const URL: &str =
    "https://github.com/hashgraph-online/hol-cigar/releases/download/v0.14.1/test.whl";
impl PinnedHttpsTransport for Mock {
    fn validate_destination(
        &self,
        value: &CanonicalDestination,
    ) -> Result<(), RestrictedDownloadError> {
        transport::Transport {
            source: &self.source,
            cancel: Arc::new(AtomicBool::new(false)),
            allow_public_registries: true,
        }
        .validate_destination(value)
    }
    fn open_pinned_https_response(
        &self,
        _: &CanonicalDestination,
        _: &str,
        _: Instant,
    ) -> Result<Box<dyn ReadableResponse>, RestrictedDownloadError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(
            self.pending
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected request"),
        ))
    }
}
fn lock(bytes: &[u8]) -> WheelLock {
    WheelLock {
        distribution: "hol-cigar".into(),
        version: "0.14.1".into(),
        filename: "test.whl".into(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
        bytes: bytes.len() as u64,
        requires_python: None,
        source: guard_cigar_release::WheelSource::GithubCigarRelease {
            tag: "v0.14.1".into(),
        },
    }
}
fn control(cancel: Arc<AtomicBool>) -> PreparationControl {
    PreparationControl::new(cancel, Duration::from_secs(10)).unwrap()
}
fn home() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let home = fs::canonicalize(temp.path()).unwrap();
    root(&home, true).unwrap();
    let temporary = store::directory(&home, "staging", true).unwrap();
    (temp, home, temporary)
}
fn download(mock: &Mock, max: u64, temporary: &Path) -> RestrictedArchiveDownloadResult {
    download_restricted_archive(URL, max, 3, 5.0, Some(temporary), mock, mock)
}
#[test]
fn exact_download_is_cached_and_wrong_hash_length_or_changed_file_is_refused() {
    let (_temp, home, temporary) = home();
    let expected = b"synthetic locked wheel bytes; never executed";
    let lock = lock(expected);
    for body in [
        &b"wrong, same byte count but different content!"[..],
        &expected[..expected.len() - 1],
    ] {
        let result = download(&Mock::new(body), lock.bytes, &temporary);
        assert!(commit_download(
            &home,
            &lock,
            result,
            &control(Arc::new(AtomicBool::new(false)))
        )
        .is_err());
        assert!(cache::cached(&home, &lock).unwrap().is_none());
    }
    let result = download(&Mock::new(expected), lock.bytes, &temporary);
    let RestrictedArchiveDownloadResult::Success(ref file) = result else {
        panic!("download failed")
    };
    // Stable bytes are checked again even if a result's earlier hash matched.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&file.path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(windows)]
    {
        let mut permissions = fs::metadata(&file.path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&file.path, permissions).unwrap();
    }
    fs::write(&file.path, b"changed after download").unwrap();
    assert!(commit_download(
        &home,
        &lock,
        result,
        &control(Arc::new(AtomicBool::new(false)))
    )
    .is_err());
    assert!(cache::cached(&home, &lock).unwrap().is_none());
    let result = download(&Mock::new(expected), lock.bytes, &temporary);
    let path = commit_download(
        &home,
        &lock,
        result,
        &control(Arc::new(AtomicBool::new(false))),
    )
    .unwrap();
    assert_eq!(fs::read(&path).unwrap(), expected);
    assert_eq!(cache::cached(&home, &lock).unwrap(), Some(path));
    assert_eq!(fs::read_dir(&temporary).unwrap().count(), 0);
    assert!(!home
        .join("context-assistance/installation-authority.json")
        .exists());
}
#[test]
fn over_limit_or_cancelled_body_never_publishes_and_staged_bytes_are_cleaned() {
    let (_temp, home, temporary) = home();
    let lock = lock(b"locked");
    let result = download(
        &Mock::new(b"body exceeds the exact wheel size"),
        lock.bytes,
        &temporary,
    );
    assert!(matches!(
        result,
        RestrictedArchiveDownloadResult::Failure(_)
    ));
    assert!(commit_download(
        &home,
        &lock,
        result,
        &control(Arc::new(AtomicBool::new(false)))
    )
    .is_err());
    let result = download(&Mock::new(b"locked"), lock.bytes, &temporary);
    let cancel = Arc::new(AtomicBool::new(false));
    let control = control(Arc::clone(&cancel));
    cancel.store(true, Ordering::Release);
    assert_eq!(
        commit_download(&home, &lock, result, &control),
        Err(error("cigar_install_cancelled"))
    );
    assert!(cache::cached(&home, &lock).unwrap().is_none());
    assert_eq!(fs::read_dir(&temporary).unwrap().count(), 0);
}
#[test]
fn untrusted_redirect_is_refused_before_destination_dns_or_request() {
    let (_temp, _home, temporary) = home();
    let mock = Mock::new(b"");
    *mock.pending.lock().unwrap() = VecDeque::from([Response {
        status: 302,
        bytes: VecDeque::new(),
        location: Some("https://other.example/untrusted.whl".into()),
    }]);
    let result = download(&mock, 10, &temporary);
    let RestrictedArchiveDownloadResult::Failure(value) = result else {
        panic!("redirect was followed")
    };
    assert_eq!(value.code, "install_origin_rejected");
    assert_eq!(mock.resolutions.load(Ordering::SeqCst), 1);
    assert_eq!(mock.opens.load(Ordering::SeqCst), 1);
    assert_eq!(fs::read_dir(&temporary).unwrap().count(), 0);
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[ignore = "Explicit network qualification: exact public GitHub CIGAR 0.14.1 and files.pythonhosted.org dependency bytes, private disposable profile only"]
fn actual_published_0141_wheels_acquire_without_python_or_activation() {
    let (_temp, home, _temporary) = home();
    let catalog = guard_cigar_release::TrustedCatalog::bundled().unwrap();
    let build = &catalog.document().builds[0];
    let release = catalog
        .prepare(&build.identity.build_id, "darwin-arm64", false)
        .unwrap();
    assert!(!release.activation_qualified());
    let request = store::InstallRequest {
        job_id: "public-download-qualification".into(),
        build_id: build.identity.build_id.clone(),
        interpreter_id: "unused:no-python".into(),
    };
    let now = store::now().unwrap();
    let slot = guard_cigar_install::slot_id(&release, &"a".repeat(64)).unwrap();
    let job = store::Job {
        schema: "guard-cigar-install-job.v1".into(),
        request_sha256: store::request_sha(&request).unwrap(),
        request,
        release: release.binding().unwrap(),
        package_tree_sha256: release.platform().package_tree_sha256.clone().unwrap(),
        worker_sha256: release.platform().worker_sha256.clone(),
        python_sha256: "a".repeat(64),
        python_bundle: None,
        runtime_id: format!("cigar:{slot}"),
        refresh: None,
        slot,
        phase: store::Phase::Acquiring,
        code: "acquiring".into(),
        created_at_ms: now,
        updated_at_ms: now,
        deadline_at_ms: now + 120_000,
    };
    let _lease = store::lease(&home).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let control = PreparationControl::new(Arc::clone(&cancel), Duration::from_secs(120)).unwrap();
    let started = Instant::now();
    let paths = acquire(&home, &job, &release, &control, Arc::clone(&cancel)).unwrap();
    let plan = guard_cigar_install::prepare_locked(&release, &paths, &control).unwrap();
    assert_eq!(
        plan.tree_sha256(),
        "5ebfc715f581c40c9fce73209271479a1926d5044543a46c720ba0049c35e1f4"
    );
    let again = acquire(&home, &job, &release, &control, cancel).unwrap();
    assert_eq!(paths, again);
    assert_eq!(
        store::directory(&home, "downloads", false)
            .unwrap()
            .read_dir()
            .unwrap()
            .count(),
        0
    );
    assert!(!home.join("context-assistance/bundles").exists());
    assert!(!home.join("context-assistance/work").exists());
    assert!(!home
        .join("context-assistance/installation-authority.json")
        .exists());
    let settings = crate::guard_config_load::context_assistance_config(&home).unwrap();
    assert!(!settings.requested.enabled);
    assert!(settings.requested.runtime_id.is_empty());
    println!(
        "CIGAR_PUBLIC_ACQUISITION_PROOF {}",
        serde_json::json!({"build_id":job.release.identity.build_id,
        "sdk_version":job.release.identity.sdk_version,"wheels":paths.len(),"files":plan.files(),"expanded_bytes":plan.bytes(),
        "tree_sha256":plan.tree_sha256(),"elapsed_ms":started.elapsed().as_millis(),"activation_granted":false,
        "sdk_processes_started":0,"cached_retry_equal":true})
    );
}

#[test]
fn catalog_fetch_is_exact_source_has_no_redirects_and_bounds_the_envelope() {
    let (_temp, _home, temporary) = home();
    const FEED: &str = "https://catalog.example.com/cigar.json";
    let bytes = b"synthetic signed envelope bytes, not executed";
    let mut mock = Mock::new(bytes);
    mock.source = FEED.into();
    let result = catalog_download(FEED, &temporary, 5.0, &mock, &mock);
    let RestrictedArchiveDownloadResult::Success(file) = result else {
        panic!("catalog download failed");
    };
    assert_eq!(fs::read(&file.path).unwrap(), bytes);
    file.cleanup();
    for location in [FEED, "https://other.example.com/catalog.json"] {
        let mut mock = Mock::new(b"");
        mock.source = FEED.into();
        *mock.pending.lock().unwrap() = VecDeque::from([Response {
            status: 302,
            bytes: VecDeque::new(),
            location: Some(location.into()),
        }]);
        assert!(matches!(
            catalog_download(FEED, &temporary, 5.0, &mock, &mock),
            RestrictedArchiveDownloadResult::Failure(_)
        ));
        assert_eq!(mock.resolutions.load(Ordering::SeqCst), 1);
        assert_eq!(mock.opens.load(Ordering::SeqCst), 1);
    }
    let mut mock = Mock::new(&vec![b'x'; guard_cigar_release::MAX_ENVELOPE_BYTES + 1]);
    mock.source = FEED.into();
    assert!(matches!(
        catalog_download(FEED, &temporary, 5.0, &mock, &mock),
        RestrictedArchiveDownloadResult::Failure(_)
    ));
    assert_eq!(fs::read_dir(&temporary).unwrap().count(), 0);
    let wrong = Mock::new(b"no request permitted");
    assert!(matches!(
        catalog_download(FEED, &temporary, 5.0, &wrong, &wrong),
        RestrictedArchiveDownloadResult::Failure(_)
    ));
    assert_eq!(wrong.resolutions.load(Ordering::SeqCst), 0);
    assert_eq!(wrong.opens.load(Ordering::SeqCst), 0);
}
