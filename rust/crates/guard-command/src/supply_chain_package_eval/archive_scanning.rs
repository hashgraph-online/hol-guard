use super::*;

/// `_external_archive_request_timeout_result` (:3849-3855).
// supply_chain_package_eval.py:3849-3855
#[allow(dead_code)]
pub(super) fn external_archive_request_timeout_result() -> Map<String, Value> {
    let mut r = Map::new();
    r.insert("decision".to_string(), Value::String("block".to_string()));
    r.insert(
        "code".to_string(),
        Value::String("external_archive_request_timeout".to_string()),
    );
    r.insert(
        "message".to_string(),
        Value::String(
            "External archive request exceeded Guard's aggregate time limit.".to_string(),
        ),
    );
    r.insert("severity".to_string(), Value::String("high".to_string()));
    r
}

/// `_download_external_tarball` (:3858-3867).
/// `download_restricted_archive(source_url, max_bytes=, timeout_seconds=)`.
// supply_chain_package_eval.py:3858-3867
#[allow(dead_code)]
pub(super) fn download_external_tarball(
    deps: &SupplyChainEvalDeps<'_>,
    source_url: &str,
    timeout_seconds: f64,
    guard_home: &Path,
) -> Option<RestrictedArchiveDownloadResult> {
    deps.archive
        .download_restricted_archive(
            source_url,
            TARBALL_SCAN_MAX_BYTES,
            3,
            timeout_seconds,
            Some(guard_home),
        )
        .ok()
}

/// `_scan_external_tarball` (:3779-3846).
/// Returns `(result_dict, retained_download)`. The caller retains ownership of
/// the download path only when `retain_download` requests it; otherwise the
/// seam-owned temp file is dropped (Python `downloaded.cleanup()`).
// supply_chain_package_eval.py:3779-3846
#[allow(dead_code)]
pub(super) fn scan_external_tarball(
    deps: &SupplyChainEvalDeps<'_>,
    source_url: &str,
    retain_download: bool,
    request_deadline: Option<f64>,
    guard_home: &Path,
) -> (
    Option<Map<String, Value>>,
    Option<RestrictedArchiveDownload>,
) {
    let mut download_timeout = TARBALL_SCAN_TIMEOUT_SECONDS as f64;
    if let Some(deadline) = request_deadline {
        let remaining = deadline - monotonic_seconds();
        if remaining <= 0.0 {
            return (Some(external_archive_request_timeout_result()), None);
        }
        download_timeout = download_timeout.min(remaining);
    }
    let downloaded = match download_external_tarball(deps, source_url, download_timeout, guard_home)
    {
        Some(d) => d,
        None => return (None, None),
    };
    let downloaded = match downloaded {
        RestrictedArchiveDownloadResult::Failure(f) => {
            let mut r = Map::new();
            r.insert("decision".to_string(), Value::String("block".to_string()));
            r.insert("code".to_string(), Value::String(f.code));
            r.insert("message".to_string(), Value::String(f.message));
            r.insert("severity".to_string(), Value::String("high".to_string()));
            return (Some(r), None);
        }
        RestrictedArchiveDownloadResult::Success(d) => d,
    };
    // try/finally: when retain_blob is false the temp blob is dropped.
    let mut retain_blob = false;
    let outcome = (|| {
        let mut inspection_timeout = TARBALL_SCAN_TIMEOUT_SECONDS as f64;
        if let Some(deadline) = request_deadline {
            // Reserve a 0.5s termination grace for the inspector parent.
            let remaining = deadline - monotonic_seconds() - 0.5;
            if remaining <= 0.0 {
                return (Some(external_archive_request_timeout_result()), None);
            }
            inspection_timeout = inspection_timeout.min(remaining);
        }
        let inspection = match deps.native_archive.inspect_archive_native(
            &downloaded.path,
            &downloaded.sha256,
            guard_home,
            inspection_timeout,
            TARBALL_SCAN_MAX_BYTES,
            TARBALL_SCAN_MAX_FILES as u64,
            u64::MAX,
            u64::MAX,
            TARBALL_SCAN_MAX_PACKAGE_JSON_BYTES,
            u64::MAX,
            f64::MAX,
            u64::MAX,
            u64::MAX,
        ) {
            Ok(i) => i,
            Err(_) => return (None, None),
        };
        let status = optional_string(inspection.get("status")).unwrap_or_default();
        if status != "clean" {
            let mut r = Map::new();
            r.insert("decision".to_string(), Value::String("block".to_string()));
            r.insert(
                "code".to_string(),
                Value::String(optional_string(inspection.get("code")).unwrap_or_default()),
            );
            r.insert(
                "message".to_string(),
                Value::String(optional_string(inspection.get("message")).unwrap_or_default()),
            );
            r.insert(
                "severity".to_string(),
                Value::String(
                    optional_string(inspection.get("severity"))
                        .unwrap_or_else(|| "high".to_string()),
                ),
            );
            return (Some(r), None);
        }
        retain_blob = retain_download;
        let mut r = Map::new();
        r.insert("decision".to_string(), Value::String("ask".to_string()));
        r.insert(
            "code".to_string(),
            Value::String("external_tarball_source".to_string()),
        );
        r.insert(
            "message".to_string(),
            Value::String(
                "External tarball source requires review before any archive download.".to_string(),
            ),
        );
        r.insert("severity".to_string(), Value::String("medium".to_string()));
        r.insert(
            "source".to_string(),
            Value::String("guard-local".to_string()),
        );
        (Some(r), if retain_blob { Some(downloaded) } else { None })
    })();
    // Drop `downloaded` when not retained (mirrors `downloaded.cleanup()`).
    outcome
}
