//! Bounded acquisition on existing resident workers, separate from inspection.

use guard_archive::content_coding::parse_content_codings;
use guard_command::restricted_archive::{
    canonical_destination, download_restricted_archive, download_restricted_content,
    RestrictedArchiveDownloadResult, RestrictedDownloadError,
};
use guard_command::restricted_archive_transport::{
    validate_managed_destination, ManagedUreqPinnedTransport, SystemDnsResolver,
};
use guard_contracts::*;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static ACTIVE_DOWNLOADS: AtomicUsize = AtomicUsize::new(0);
const MAX_ACTIVE_DOWNLOADS: usize = 2;

struct DownloadAdmission;
impl DownloadAdmission {
    fn acquire() -> Option<Self> {
        ACTIVE_DOWNLOADS
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < MAX_ACTIVE_DOWNLOADS).then_some(count + 1)
            })
            .ok()
            .map(|_| Self)
    }
}
impl Drop for DownloadAdmission {
    fn drop(&mut self) {
        ACTIVE_DOWNLOADS.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) fn evaluate_archive_acquisition_request(
    request: &ArchiveAcquisitionRequestV1,
) -> Result<Vec<u8>, String> {
    let digest = crate::package_authority_op::request_digest_with_limit(
        request,
        ARCHIVE_ACQUISITION_MAX_REQUEST_BYTES,
    )
    .map_err(|_| "native_archive_acquisition_too_large".to_owned())?;
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok", "ok".to_owned(), Some(payload)),
        Err(code) => ("error", code.to_owned(), None),
    };
    crate::encode_response(&ArchiveAcquisitionResultV1 {
        schema: ARCHIVE_ACQUISITION_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256: digest,
        status: status.to_owned(),
        code,
        payload,
    })
}

fn evaluate(request: &ArchiveAcquisitionRequestV1) -> Result<Value, &'static str> {
    if request.schema != ARCHIVE_ACQUISITION_REQUEST_SCHEMA {
        return Err("native_archive_acquisition_schema_mismatch");
    }
    if request.request_id.is_empty()
        || request.request_id.len() > 128
        || request.guard_home.len() > 4096
        || !Path::new(&request.guard_home).is_absolute()
    {
        return Err("native_archive_acquisition_invalid");
    }
    let query = &request.query;
    if query.source_url.len() > ARCHIVE_ACQUISITION_MAX_URL_BYTES {
        return Err("native_archive_acquisition_too_large");
    }
    if query.action == ArchiveAcquisitionActionV1::Destination {
        let canonical = canonical_destination(&query.source_url)
            .ok()
            .map(|destination| destination.url);
        return Ok(json!({"kind": "destination", "canonical_url": canonical,
            "is_external": guard_command::restricted_archive::is_external_https_archive_source(&query.source_url)}));
    }
    let max_bytes = if query.action == ArchiveAcquisitionActionV1::Content {
        CONTENT_CAP_INPUT_BYTES
    } else {
        ARCHIVE_ACQUISITION_MAX_BYTES
    };
    if query.max_bytes <= 0
        || query.max_bytes > max_bytes as i64
        || !(0..=4).contains(&query.max_redirects)
        || query.timeout_ms <= 0
        || query.timeout_ms > ARCHIVE_ACQUISITION_MAX_TIMEOUT_MS as i64
    {
        return Ok(failure(
            "external_archive_download_policy_invalid",
            "External archive download policy is invalid.",
        ));
    }
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "native_archive_acquisition_invalid")?
        .as_millis();
    let remaining_ms = u128::from(query.expires_at_unix_ms).saturating_sub(now_ms);
    if remaining_ms == 0 {
        return Ok(failure(
            "external_archive_download_timeout",
            "External archive download exceeded Guard's time limit.",
        ));
    }
    let timeout_ms = (query.timeout_ms as u128).min(remaining_ms) as u64;
    if query
        .temp_dir
        .as_ref()
        .is_some_and(|path| path.len() > 4096 || !Path::new(path).is_absolute())
    {
        return Err("native_archive_acquisition_invalid");
    }
    if !query.allow_public_registries {
        if let Ok(destination) = canonical_destination(&query.source_url) {
            if let Err(error) = validate_managed_destination(&destination, false) {
                return Ok(failure(&error.code, &error.message));
            }
        }
    }
    if query.trust_roots_der_hex.is_empty()
        || query.trust_roots_der_hex.len() > ARCHIVE_ACQUISITION_MAX_ROOTS
    {
        return Ok(failure(
            "external_archive_tls_error",
            "External archive TLS verification failed.",
        ));
    }
    let mut roots = Vec::new();
    for encoded in &query.trust_roots_der_hex {
        if encoded.len() > ARCHIVE_ACQUISITION_MAX_CERT_BYTES * 2 {
            return Err("native_archive_acquisition_too_large");
        }
        let Ok(der) = hex::decode(encoded) else {
            return Err("native_archive_acquisition_invalid");
        };
        if der.is_empty() {
            return Err("native_archive_acquisition_invalid");
        }
        roots.push(der);
    }
    let Some(_admission) = DownloadAdmission::acquire() else {
        return Ok(failure(
            "external_archive_download_timeout",
            "External archive operation capacity is unavailable.",
        ));
    };
    let transport = ManagedUreqPinnedTransport {
        roots,
        allow_public_registries: query.allow_public_registries,
    };
    let temp_dir = query.temp_dir.as_deref().map(Path::new);
    let timeout_seconds = timeout_ms as f64 / 1000.0;
    if query.action == ArchiveAcquisitionActionV1::Content {
        let (result, codings) = download_restricted_content(
            &query.source_url,
            query.max_bytes as u64,
            query.max_redirects as u32,
            timeout_seconds,
            temp_dir,
            &SystemDnsResolver,
            &transport,
            &supported_content_codings,
        );
        return Ok(match result {
            RestrictedArchiveDownloadResult::Failure(error) => failure(&error.code, &error.message),
            RestrictedArchiveDownloadResult::Success(download) => json!({
                "kind": "content", "path": download.path, "sha256": download.sha256,
                "size": download.size, "source_url": download.source_url,
                "final_url": download.final_url, "content_encoding": codings,
            }),
        });
    }
    let result = download_restricted_archive(
        &query.source_url,
        query.max_bytes as u64,
        query.max_redirects as u32,
        timeout_seconds,
        temp_dir,
        &SystemDnsResolver,
        &transport,
    );
    Ok(match result {
        RestrictedArchiveDownloadResult::Failure(error) => failure(&error.code, &error.message),
        RestrictedArchiveDownloadResult::Success(download) => json!({
            "kind": "download", "path": download.path, "sha256": download.sha256,
            "size": download.size, "source_url": download.source_url, "final_url": download.final_url,
        }),
    })
}

/// Every hop of a managed content fetch must carry only codings the
/// contained decoder accepts, in a stack no deeper than its ceiling, and no
/// more header lines than it will take. This is the same parser the worker
/// runs, so the fetch never spools a body no worker policy could accept. A
/// caller's tighter layer cap is applied by the worker, before any decoder.
fn supported_content_codings(values: &[String]) -> Result<(), RestrictedDownloadError> {
    let refused = |code: &str, message: &str| RestrictedDownloadError {
        code: code.to_owned(),
        message: message.to_owned(),
    };
    if values.len() > CONTENT_CAP_HEADER_VALUES {
        return Err(refused(
            "content_coding_unsupported",
            "The response uses a content coding Guard does not decode.",
        ));
    }
    let values: Vec<&str> = values.iter().map(String::as_str).collect();
    parse_content_codings(&values, CONTENT_CAP_LAYERS as usize)
        .map(|_| ())
        .map_err(|error| refused(error.code, error.message))
}

fn failure(code: &str, message: &str) -> Value {
    json!({"kind": "failure", "code": code, "message": message})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ArchiveAcquisitionRequestV1 {
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        ArchiveAcquisitionRequestV1 {
            schema: ARCHIVE_ACQUISITION_REQUEST_SCHEMA.into(),
            request_id: "test-acquisition".into(),
            guard_home: std::env::temp_dir().to_string_lossy().into_owned(),
            query: ArchiveAcquisitionQueryV1 {
                action: ArchiveAcquisitionActionV1::Download,
                source_url: "https://packages.example.com/a.tgz?signature=synthetic".into(),
                max_bytes: ARCHIVE_ACQUISITION_MAX_BYTES as i64,
                max_redirects: 4,
                timeout_ms: 1000,
                expires_at_unix_ms: expiry + 1000,
                temp_dir: None,
                trust_roots_der_hex: vec![],
                allow_public_registries: true,
            },
        }
    }

    #[test]
    fn archive_acquisition_dispatch_binds_result_without_network() {
        let mut request = request();
        request.query.action = ArchiveAcquisitionActionV1::Destination;
        let envelope =
            serde_json::to_vec(&json!({"operation": "archive_acquisition", "request": request}))
                .unwrap();
        let bytes = crate::resident_ops::evaluate_resident_bytes(&envelope, None).unwrap();
        let result: ArchiveAcquisitionResultV1 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result.request_id, request.request_id);
        assert_eq!(
            result.request_sha256,
            crate::package_authority_op::request_digest_with_limit(
                &request,
                ARCHIVE_ACQUISITION_MAX_REQUEST_BYTES
            )
            .unwrap()
        );
        assert_eq!(
            result.payload.unwrap()["canonical_url"],
            request.query.source_url
        );
        assert!(!format!("{request:?}").contains("signature"));
    }

    #[test]
    fn archive_acquisition_expiry_and_caps_fail_before_network() {
        let mut request = request();
        request.query.expires_at_unix_ms = 1;
        assert_eq!(
            evaluate(&request).unwrap()["code"],
            "external_archive_download_timeout"
        );
        request.query.max_bytes += 1;
        assert_eq!(
            evaluate(&request).unwrap()["code"],
            "external_archive_download_policy_invalid"
        );
    }

    #[test]
    fn archive_acquisition_signed_invalid_limits_return_policy_failure() {
        for field in ["max_bytes", "max_redirects", "timeout_ms"] {
            let mut encoded = serde_json::to_value(request()).unwrap();
            encoded["query"][field] = json!(-1);
            let decoded: ArchiveAcquisitionRequestV1 = serde_json::from_value(encoded).unwrap();
            assert_eq!(
                evaluate(&decoded).unwrap()["code"],
                "external_archive_download_policy_invalid"
            );
        }
    }

    #[test]
    fn managed_content_codings_are_refused_with_the_decoder_parser() {
        let owned = |values: &[&str]| values.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>();
        for allowed in [&[][..], &["br"][..], &["gzip, br"][..], &["identity"][..]] {
            assert!(
                supported_content_codings(&owned(allowed)).is_ok(),
                "{allowed:?}"
            );
        }
        for (values, code) in [
            (&["zstd"][..], "content_coding_unsupported"),
            (&["br;q=1"][..], "content_coding_unsupported"),
            (
                &["gzip, gzip, gzip, gzip, br"][..],
                "content_coding_too_deep",
            ),
            (
                &["identity"; CONTENT_CAP_HEADER_VALUES + 1][..],
                "content_coding_unsupported",
            ),
        ] {
            assert_eq!(
                supported_content_codings(&owned(values)).unwrap_err().code,
                code
            );
        }
    }

    #[test]
    fn managed_content_body_cap_is_the_decoder_input_cap() {
        let mut request = request();
        request.query.action = ArchiveAcquisitionActionV1::Content;
        request.query.max_bytes = CONTENT_CAP_INPUT_BYTES as i64 + 1;
        assert_eq!(
            evaluate(&request).unwrap()["code"],
            "external_archive_download_policy_invalid"
        );
        request.query.max_bytes = CONTENT_CAP_INPUT_BYTES as i64;
        assert_eq!(
            evaluate(&request).unwrap()["code"],
            "external_archive_tls_error"
        );
    }

    #[test]
    fn archive_acquisition_managed_registry_and_missing_trust_fail_closed() {
        let mut request = request();
        assert_eq!(
            evaluate(&request).unwrap()["code"],
            "external_archive_tls_error"
        );
        request.query.source_url = "https://files.pythonhosted.org/a.tgz".into();
        request.query.allow_public_registries = false;
        assert_eq!(
            evaluate(&request).unwrap()["code"],
            "managed_public_registry_disabled"
        );
    }
}
