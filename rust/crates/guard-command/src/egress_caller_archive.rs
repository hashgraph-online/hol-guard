//! External archives the caller acquires for the resident's supply-chain
//! evaluation.
//!
//! The resident never downloads an archive for a package evaluation: it names
//! the archive as an `archive` need and the caller acquires it under the
//! managed network policy, inspects the blob offline with the network-denied
//! worker, and reports the digest, size and verdict. The resident still owns
//! what the verdict means.
//!
//! Port of `native_supply_chain_archive.py`'s `ArchiveFulfilment`, with the
//! same accounting: the inspection spec's aggregate timeout covers every
//! archive of one request, download and inspection together, and the
//! inspection keeps a grace period back for the worker parent's termination.
//!
//! With `retain` a verified blob is kept so a reviewed launch can run against
//! the bytes that were inspected; [`ArchiveFulfilment::claim`] hands over the
//! blobs the resident's answer names and removes the rest.

use std::path::{Path, PathBuf};
use std::time::Instant;

use guard_contracts::{ArchiveInspectionSpecV1, ArchiveVerdictV1, EgressNeedV1, EgressOutcomeV1};
use serde_json::Value;

use crate::archive_inspection::{
    inspect_archive_native, ArchiveInspectionResult, IsolatedHookProcessApi,
    NativeRuntimeStatusApi, DEFAULT_MAX_DECOMPRESSION_RATIO, DEFAULT_MAX_EXPANDED_BYTES,
    DEFAULT_MAX_MEMBER_BYTES, DEFAULT_MAX_MEMORY_BYTES, DEFAULT_MAX_NESTED_ARCHIVES,
    DEFAULT_MAX_PATH_DEPTH,
};
use crate::egress_caller::{
    policy_code, ArchiveEgress, EgressPolicy, ARCHIVE_POLICY_REFUSAL_MESSAGE,
};
use crate::local_supply_chain::stable_digest_hex;
use crate::restricted_archive::{
    download_restricted_archive, CanonicalDestination, DnsResolver, PinnedHttpsTransport,
    ReadableResponse, RestrictedArchiveDownload, RestrictedArchiveDownloadResult,
    RestrictedDownloadError,
};

/// Time kept back for the inspection worker parent's termination grace.
const INSPECTION_GRACE_SECONDS: f64 = 0.5;
const TIMEOUT_CODE: &str = "external_archive_request_timeout";
const TIMEOUT_MESSAGE: &str = "External archive request exceeded Guard's aggregate time limit.";
const SCRATCH_CODE: &str = "external_archive_scratch_unavailable";
const SCRATCH_MESSAGE: &str = "External archive scratch directory is unavailable.";
/// A blob the resident's answer names but this caller does not hold.
pub const UNHELD_ARCHIVE: &str = "resident named an archive this caller does not hold";

/// Bounded acquisition of one external archive.
pub trait ArchiveDownloadApi {
    /// `download_restricted_archive(...)`. `temp_dir` is `None` when the blob
    /// must outlive the request's scratch directory.
    fn download(
        &self,
        url: &str,
        max_bytes: u64,
        max_redirects: u32,
        timeout_seconds: f64,
        temp_dir: Option<&Path>,
    ) -> RestrictedArchiveDownloadResult;
}

/// Offline inspection of one downloaded archive by the network-denied worker.
pub trait ArchiveInspectApi {
    /// `inspect_archive_native(...)`.
    fn inspect(
        &self,
        path: &Path,
        expected_sha256: &str,
        timeout_seconds: f64,
        max_archive_bytes: u64,
        max_files: u64,
        max_package_json_bytes: u64,
    ) -> ArchiveInspectionResult;
}

/// Acquisition through the pinned transport under the managed network policy.
///
/// The policy is not advisory here: it is bound to the transport, so the
/// destination and every redirect are validated before DNS or a socket, the
/// same answer the caller's HTTP needs get.
pub struct NativeArchiveDownload<'a> {
    pub resolver: &'a dyn DnsResolver,
    pub transport: &'a dyn PinnedHttpsTransport,
    pub policy: &'a (dyn EgressPolicy + Send + Sync),
}

impl ArchiveDownloadApi for NativeArchiveDownload<'_> {
    fn download(
        &self,
        url: &str,
        max_bytes: u64,
        max_redirects: u32,
        timeout_seconds: f64,
        temp_dir: Option<&Path>,
    ) -> RestrictedArchiveDownloadResult {
        let bound = PolicyBoundTransport {
            inner: self.transport,
            policy: self.policy,
        };
        download_restricted_archive(
            url,
            max_bytes,
            max_redirects,
            timeout_seconds,
            temp_dir,
            self.resolver,
            &bound,
        )
    }
}

/// A pinned transport bound to the caller's managed network policy.
///
/// `download_restricted_archive` validates every hop through the transport, so
/// a destination the policy refuses never reaches DNS, and a redirect cannot
/// carry the download to a host the policy would have refused.
pub struct PolicyBoundTransport<'a> {
    pub inner: &'a dyn PinnedHttpsTransport,
    pub policy: &'a (dyn EgressPolicy + Send + Sync),
}

impl PinnedHttpsTransport for PolicyBoundTransport<'_> {
    fn validate_destination(
        &self,
        destination: &CanonicalDestination,
    ) -> Result<(), RestrictedDownloadError> {
        if let Err(code) = self.policy.validate(&destination.url) {
            return Err(RestrictedDownloadError::new(
                &policy_code(&code),
                ARCHIVE_POLICY_REFUSAL_MESSAGE,
            ));
        }
        self.inner.validate_destination(destination)
    }

    fn open_pinned_https_response(
        &self,
        destination: &CanonicalDestination,
        address: &str,
        deadline: Instant,
    ) -> Result<Box<dyn ReadableResponse>, RestrictedDownloadError> {
        self.inner
            .open_pinned_https_response(destination, address, deadline)
    }
}

/// Inspection by the native archive-inspect worker.
pub struct NativeArchiveInspection<'a> {
    pub guard_home: PathBuf,
    pub runtime_status: &'a dyn NativeRuntimeStatusApi,
    pub process: &'a dyn IsolatedHookProcessApi,
}

impl ArchiveInspectApi for NativeArchiveInspection<'_> {
    fn inspect(
        &self,
        path: &Path,
        expected_sha256: &str,
        timeout_seconds: f64,
        max_archive_bytes: u64,
        max_files: u64,
        max_package_json_bytes: u64,
    ) -> ArchiveInspectionResult {
        inspect_archive_native(
            path,
            expected_sha256,
            &self.guard_home,
            timeout_seconds,
            max_archive_bytes,
            max_files,
            DEFAULT_MAX_EXPANDED_BYTES,
            DEFAULT_MAX_MEMBER_BYTES,
            max_package_json_bytes,
            DEFAULT_MAX_MEMORY_BYTES,
            DEFAULT_MAX_DECOMPRESSION_RATIO,
            DEFAULT_MAX_NESTED_ARCHIVES,
            DEFAULT_MAX_PATH_DEPTH,
            self.runtime_status,
            self.process,
        )
    }
}

/// Downloads and inspects the archives one evaluation asks for.
pub struct ArchiveFulfilment<'a> {
    scratch_dir: PathBuf,
    retain: bool,
    /// Seconds already charged against the aggregate timeout.
    elapsed: f64,
    retained: Vec<RestrictedArchiveDownload>,
    downloads: &'a dyn ArchiveDownloadApi,
    inspections: &'a dyn ArchiveInspectApi,
}

impl<'a> ArchiveFulfilment<'a> {
    pub fn new(
        scratch_dir: &Path,
        retain: bool,
        downloads: &'a dyn ArchiveDownloadApi,
        inspections: &'a dyn ArchiveInspectApi,
    ) -> Self {
        Self {
            scratch_dir: scratch_dir.to_path_buf(),
            retain,
            elapsed: 0.0,
            retained: Vec::new(),
            downloads,
            inspections,
        }
    }

    /// Time already charged plus the in-flight call, including its download.
    fn spent(&self, started: Instant) -> f64 {
        self.elapsed + started.elapsed().as_secs_f64()
    }

    fn acquire(&mut self, need: &EgressNeedV1, started: Instant) -> EgressOutcomeV1 {
        let aggregate = need
            .inspect
            .as_ref()
            .map(|spec| spec.aggregate_timeout_seconds)
            .filter(|seconds| seconds.is_finite());
        let mut download_timeout = need.timeout_seconds;
        if let Some(aggregate) = aggregate {
            let remaining = aggregate - self.spent(started);
            if remaining <= 0.0 {
                return failure(TIMEOUT_CODE, TIMEOUT_MESSAGE);
            }
            download_timeout = download_timeout.min(remaining);
        }
        // A retained blob lives where the caller's launch can reach it; the
        // rest stay in a private scratch directory and are removed as soon as
        // they have been inspected.
        let scratch = match ScratchDir::create(&self.scratch_dir) {
            Ok(scratch) => scratch,
            Err(()) => return failure(SCRATCH_CODE, SCRATCH_MESSAGE),
        };
        let download = match self.downloads.download(
            &need.url,
            need.max_response_bytes,
            need.max_redirects,
            download_timeout,
            if self.retain {
                None
            } else {
                Some(scratch.path())
            },
        ) {
            RestrictedArchiveDownloadResult::Failure(error) => {
                return EgressOutcomeV1::ArchiveFailure {
                    code: error.code,
                    message: error.message,
                }
            }
            RestrictedArchiveDownloadResult::Success(download) => download,
        };
        let mut keep = self.retain;
        let mut inspection = None;
        if let Some(spec) = need.inspect.as_ref() {
            match self.inspect(&download, need, spec, aggregate, started) {
                None => {
                    download.cleanup();
                    return failure(TIMEOUT_CODE, TIMEOUT_MESSAGE);
                }
                Some(verdict) => {
                    keep = self.retain && verdict.status == "clean";
                    inspection = Some(verdict);
                }
            }
        }
        let outcome = EgressOutcomeV1::Archive {
            sha256: download.sha256.clone(),
            size: download.size,
            final_url: download.final_url.clone(),
            inspection,
        };
        if keep {
            self.retained.push(download);
        } else {
            download.cleanup();
        }
        outcome
    }

    /// `None` when the aggregate timeout leaves no time to inspect.
    fn inspect(
        &self,
        download: &RestrictedArchiveDownload,
        need: &EgressNeedV1,
        spec: &ArchiveInspectionSpecV1,
        aggregate: Option<f64>,
        started: Instant,
    ) -> Option<ArchiveVerdictV1> {
        let mut timeout = spec.timeout_seconds;
        if let Some(aggregate) = aggregate {
            let remaining = aggregate - self.spent(started) - INSPECTION_GRACE_SECONDS;
            if remaining <= 0.0 {
                return None;
            }
            timeout = timeout.min(remaining);
        }
        let inspection = self.inspections.inspect(
            &download.path,
            &download.sha256,
            timeout,
            need.max_response_bytes,
            spec.max_files,
            spec.max_package_json_bytes,
        );
        Some(ArchiveVerdictV1 {
            status: inspection.status,
            code: inspection.code,
            message: inspection.message,
            severity: inspection.severity,
        })
    }

    /// Hand over the retained blobs the resident's answer names; remove the
    /// rest.
    ///
    /// An answer that names a blob this caller does not hold is a protocol
    /// failure: the caller must not launch against bytes nobody inspected.
    pub fn claim(
        &mut self,
        descriptors: &Value,
    ) -> Result<Vec<RestrictedArchiveDownload>, &'static str> {
        let wanted = descriptors.as_array().map(Vec::as_slice).unwrap_or(&[]);
        let mut pool = std::mem::take(&mut self.retained);
        let mut claimed = Vec::new();
        for descriptor in wanted {
            match take_match(&mut pool, descriptor) {
                Some(download) => claimed.push(download),
                None => {
                    for download in claimed.iter().chain(pool.iter()) {
                        download.cleanup();
                    }
                    return Err(UNHELD_ARCHIVE);
                }
            }
        }
        for download in &pool {
            download.cleanup();
        }
        Ok(claimed)
    }

    /// Remove every retained blob.
    pub fn discard(&mut self) {
        for download in std::mem::take(&mut self.retained) {
            download.cleanup();
        }
    }
}

impl ArchiveEgress for ArchiveFulfilment<'_> {
    fn fulfil(&mut self, need: &EgressNeedV1) -> EgressOutcomeV1 {
        let started = Instant::now();
        let outcome = self.acquire(need, started);
        self.elapsed += started.elapsed().as_secs_f64();
        outcome
    }

    fn claim(
        &mut self,
        descriptors: &Value,
    ) -> Result<Vec<RestrictedArchiveDownload>, &'static str> {
        ArchiveFulfilment::claim(self, descriptors)
    }
}

impl Drop for ArchiveFulfilment<'_> {
    /// A caller that neither claimed nor discarded leaves no blob behind.
    fn drop(&mut self) {
        self.discard();
    }
}

fn failure(code: &str, message: &str) -> EgressOutcomeV1 {
    EgressOutcomeV1::ArchiveFailure {
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

/// A descriptor matches only when the digest, the size and both URL digests
/// are the ones this caller downloaded.
fn take_match(
    pool: &mut Vec<RestrictedArchiveDownload>,
    descriptor: &Value,
) -> Option<RestrictedArchiveDownload> {
    let descriptor = descriptor.as_object()?;
    let text = |key: &str| descriptor.get(key).and_then(Value::as_str);
    let index = pool.iter().position(|download| {
        text("sha256") == Some(download.sha256.as_str())
            && descriptor.get("size").and_then(Value::as_u64) == Some(download.size)
            && text("source_url_hash")
                == Some(stable_digest_hex(download.source_url.as_bytes()).as_str())
            && text("final_url_hash")
                == Some(stable_digest_hex(download.final_url.as_bytes()).as_str())
    })?;
    Some(pool.remove(index))
}

/// `tempfile.TemporaryDirectory(prefix="archive-", dir=scratch_dir)`.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn create(base: &Path) -> Result<Self, ()> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let pid = std::process::id();
        for attempt in 0..100u32 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.subsec_nanos())
                .unwrap_or(0);
            let candidate = base.join(format!("archive-{pid}-{attempt}-{nanos}"));
            match std::fs::create_dir(&candidate) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &candidate,
                            std::fs::Permissions::from_mode(0o700),
                        );
                    }
                    return Ok(Self { path: candidate });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(()),
            }
        }
        Err(())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
#[path = "egress_caller_archive_tests.rs"]
mod tests;
