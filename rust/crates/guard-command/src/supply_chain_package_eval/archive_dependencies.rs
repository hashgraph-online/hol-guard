use super::*;

#[allow(dead_code)]
pub(super) fn external_tarball_dependency_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
    network_authorized: bool,
    retain_download: bool,
    request_deadline: Option<f64>,
    guard_home: &Path,
) -> (
    Option<Map<String, Value>>,
    Option<RestrictedArchiveDownload>,
) {
    let Some(source_url) = optional_string(target.get("source_url")) else {
        return (
            Some(heuristic_package_result(
                target,
                "ask",
                "external_tarball_source",
                "External tarball source requires review before install.",
                "medium",
            )),
            None,
        );
    };
    if target.get("external_archive_source_integrity_invalid") == Some(&Value::Bool(true)) {
        return (
            Some(heuristic_package_result(
                target,
                "block",
                "external_archive_source_integrity_invalid",
                "External archive private source no longer matches its approved public identity.",
                "high",
            )),
            None,
        );
    }
    if !source_url.starts_with("https://") {
        return (
            Some(heuristic_package_result(
                target,
                "block",
                "external_archive_destination_rejected",
                "External archive source is not a canonical HTTPS archive URL.",
                "high",
            )),
            None,
        );
    }
    if !network_authorized {
        return (
            Some(heuristic_package_result(
                target,
                "ask",
                "external_tarball_source",
                "External tarball source requires review before any archive download.",
                "medium",
            )),
            None,
        );
    }
    let _ = request_deadline;
    match deps.archive.download_restricted_archive(
        &source_url,
        EXTERNAL_ARCHIVE_MAX_AGGREGATE_BYTES,
        3,
        EXTERNAL_ARCHIVE_REQUEST_TIMEOUT_SECONDS,
        Some(guard_home),
    ) {
        Ok(RestrictedArchiveDownloadResult::Success(download)) => {
            if !retain_download {
                return (None, None);
            }
            let mut reason = Map::new();
            reason.insert(
                "code".to_string(),
                Value::String("external_archive_scanned".into()),
            );
            reason.insert(
                "message".to_string(),
                Value::String(format!(
                    "External archive {source_url} downloaded for inspection."
                )),
            );
            reason.insert("severity".to_string(), Value::String("info".into()));
            (
                Some(package_target_result(target, "monitor", vec![reason], None)),
                Some(download),
            )
        }
        Ok(RestrictedArchiveDownloadResult::Failure(failure)) => (
            Some(heuristic_package_result(
                target,
                "block",
                &failure.code,
                &failure.message,
                "high",
            )),
            None,
        ),
        Err(_) => (
            Some(heuristic_package_result(
                target,
                "block",
                "external_archive_download_failed",
                "External archive download failed.",
                "high",
            )),
            None,
        ),
    }
}
