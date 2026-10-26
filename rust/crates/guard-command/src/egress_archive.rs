//! External-archive downloads brokered through the caller.
//!
//! The caller downloads the archive under its managed network policy, runs the
//! offline inspector on the blob it holds and reports the digest, size and the
//! inspector's verdict. The resident keeps the verdict for the evaluation and
//! decides what it means; it never sees the blob.

use std::collections::BTreeMap;

use guard_contracts::{ArchiveInspectionSpecV1, ArchiveVerdictV1, EgressOutcomeV1};

use crate::egress_broker::{
    record_inspection, recorded_inspection, resolve, EgressClass, NeedSpec, Resolution,
    NO_BROKERED_CALLER,
};
use crate::supply_chain_package_eval::{
    EXTERNAL_ARCHIVE_REQUEST_TIMEOUT_SECONDS, TARBALL_SCAN_MAX_FILES,
    TARBALL_SCAN_MAX_PACKAGE_JSON_BYTES, TARBALL_SCAN_TIMEOUT_SECONDS,
};

/// What the caller did with an external-archive need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveExchange {
    Downloaded {
        sha256: String,
        size: u64,
        final_url: String,
    },
    Failed {
        code: String,
        message: String,
    },
    /// No answer is available: the need was recorded, deferred or refused.
    Unavailable(String),
}

/// One external-archive download, answered by the caller.
pub fn exchange_archive(
    url: &str,
    max_bytes: u64,
    max_redirects: u32,
    timeout_seconds: f64,
) -> ArchiveExchange {
    let spec = NeedSpec {
        method: "GET",
        url,
        headers: BTreeMap::new(),
        body: None,
        body_sha256: String::new(),
        timeout_seconds,
        max_redirects,
        max_response_bytes: max_bytes,
        inspect: Some(ArchiveInspectionSpecV1 {
            timeout_seconds: TARBALL_SCAN_TIMEOUT_SECONDS as f64,
            aggregate_timeout_seconds: EXTERNAL_ARCHIVE_REQUEST_TIMEOUT_SECONDS,
            max_files: TARBALL_SCAN_MAX_FILES as u64,
            max_package_json_bytes: TARBALL_SCAN_MAX_PACKAGE_JSON_BYTES,
        }),
    };
    match resolve(EgressClass::Archive, &spec) {
        Some(Resolution::Supplied(
            EgressOutcomeV1::Archive {
                sha256,
                size,
                final_url,
                inspection,
            },
            _,
        )) => {
            if let Some(verdict) = inspection {
                record_inspection(&sha256, verdict);
            }
            ArchiveExchange::Downloaded {
                sha256,
                size,
                final_url,
            }
        }
        Some(Resolution::Supplied(EgressOutcomeV1::ArchiveFailure { code, message }, _)) => {
            ArchiveExchange::Failed { code, message }
        }
        Some(Resolution::Supplied(EgressOutcomeV1::Blocked { code }, _)) => {
            ArchiveExchange::Failed {
                message: "managed network policy refused the archive download".to_owned(),
                code,
            }
        }
        Some(Resolution::Supplied(..)) => {
            ArchiveExchange::Unavailable("egress outcome does not match the request".to_owned())
        }
        Some(Resolution::Unavailable(reason)) => ArchiveExchange::Unavailable(reason.to_owned()),
        None => ArchiveExchange::Unavailable(NO_BROKERED_CALLER.to_owned()),
    }
}

/// The inspector's verdict for the archive with this digest, as the caller
/// reported it with the download.
pub fn supplied_inspection(sha256: &str) -> Option<ArchiveVerdictV1> {
    recorded_inspection(sha256)
}
