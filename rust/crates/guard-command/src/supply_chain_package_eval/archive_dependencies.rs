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
    // Inspect the download before its blob is dropped: a non-retaining request
    // must still yield the scan-derived result (`_scan_external_tarball`).
    let (scan, retained_download) = super::archive_scanning::scan_external_tarball(
        deps,
        &source_url,
        retain_download,
        request_deadline,
        guard_home,
    );
    let Some(scan) = scan else {
        return (
            Some(heuristic_package_result(
                target,
                "block",
                "external_archive_inspection_incomplete",
                "Guard could not complete restricted download and offline archive inspection.",
                "high",
            )),
            None,
        );
    };
    let text = |key: &str| optional_string(scan.get(key)).unwrap_or_default();
    (
        Some(heuristic_package_result(
            target,
            &text("decision"),
            &text("code"),
            &text("message"),
            &text("severity"),
        )),
        retained_download,
    )
}
