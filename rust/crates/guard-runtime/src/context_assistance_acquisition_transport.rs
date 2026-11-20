//! Redirect allowlist plus the existing public DNS, pinned peer and TLS checks.
use guard_command::restricted_archive::{
    CanonicalDestination, DnsResolver, PinnedHttpsTransport, ReadableResponse,
    RestrictedDownloadError,
};
use guard_command::restricted_archive_transport::{
    validate_managed_destination, CancellableUreqPinnedTransport, SystemDnsResolver,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

fn refusal(code: &str) -> RestrictedDownloadError {
    RestrictedDownloadError {
        code: code.into(),
        message: "CIGAR artifact acquisition was refused.".into(),
    }
}
pub(super) struct Resolver {
    pub cancel: Arc<AtomicBool>,
}
impl DnsResolver for Resolver {
    fn getaddrinfo(&self, hostname: &str) -> Result<Option<Vec<String>>, String> {
        SystemDnsResolver.getaddrinfo(hostname)
    }
    fn resolve_with_slot(
        &self,
        hostname: &str,
        deadline: Instant,
    ) -> Result<Option<Vec<String>>, RestrictedDownloadError> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(refusal("external_archive_cancelled"));
        }
        let answer = SystemDnsResolver.resolve_with_slot(
            hostname,
            deadline.min(Instant::now() + Duration::from_secs(5)),
        );
        if self.cancel.load(Ordering::Acquire) {
            return Err(refusal("external_archive_cancelled"));
        }
        answer
    }
}
pub(super) struct Transport<'a> {
    pub source: &'a str,
    pub cancel: Arc<AtomicBool>,
    pub allow_public_registries: bool,
}
impl PinnedHttpsTransport for Transport<'_> {
    fn validate_destination(
        &self,
        destination: &CanonicalDestination,
    ) -> Result<(), RestrictedDownloadError> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(refusal("external_archive_cancelled"));
        }
        validate_managed_destination(destination, self.allow_public_registries)?;
        // The downloader already rejects non-HTTPS URLs, credentials, private
        // DNS and invalid headers. Constrain each remaining hop before DNS.
        let allowed = destination.port == 443
            && (destination.url == self.source
                || [
                    "https://github.com/hashgraph-online/hol-cigar/releases/download/",
                    "https://github.com/astral-sh/python-build-standalone/releases/download/",
                ]
                .iter()
                .any(|origin| self.source.starts_with(origin))
                    && destination.hostname == "release-assets.githubusercontent.com");
        if !allowed {
            return Err(refusal("install_origin_rejected"));
        }
        Ok(())
    }
    fn open_pinned_https_response(
        &self,
        destination: &CanonicalDestination,
        address: &str,
        deadline: Instant,
    ) -> Result<Box<dyn ReadableResponse>, RestrictedDownloadError> {
        self.validate_destination(destination)?;
        CancellableUreqPinnedTransport {
            cancel: Arc::clone(&self.cancel),
        }
        .open_pinned_https_response(destination, address, deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn destination(url: &str, hostname: &str) -> CanonicalDestination {
        CanonicalDestination {
            url: url.into(),
            hostname: hostname.into(),
            port: 443,
            request_target: "/".into(),
            host_header: hostname.into(),
        }
    }
    #[test]
    fn redirects_cannot_change_repository_or_escape_named_cdn() {
        let source =
            "https://github.com/hashgraph-online/hol-cigar/releases/download/v0.14.1/pinned.whl";
        let cancel = Arc::new(AtomicBool::new(false));
        let transport = Transport {
            source,
            cancel: Arc::clone(&cancel),
            allow_public_registries: true,
        };
        assert!(transport
            .validate_destination(&destination(source, "github.com"))
            .is_ok());
        assert!(transport
            .validate_destination(&destination(
                "https://release-assets.githubusercontent.com/path?opaque=1",
                "release-assets.githubusercontent.com"
            ))
            .is_ok());
        for (url, host) in [
            ("https://github.com/other/repo/x", "github.com"),
            ("https://example.com/x", "example.com"),
            (
                "https://release-assets.githubusercontent.com.attacker.example/x",
                "release-assets.githubusercontent.com.attacker.example",
            ),
            (
                "https://files.pythonhosted.org/packages/x",
                "files.pythonhosted.org",
            ),
        ] {
            assert!(transport
                .validate_destination(&destination(url, host))
                .is_err());
        }
        cancel.store(true, Ordering::Release);
        assert_eq!(
            transport
                .validate_destination(&destination(source, "github.com"))
                .unwrap_err()
                .code,
            "external_archive_cancelled"
        );
    }
    #[test]
    fn private_python_redirect_is_limited_to_the_exact_source_and_named_cdn() {
        let source = "https://github.com/astral-sh/python-build-standalone/releases/download/20261026/pinned.tar.gz";
        let transport = Transport {
            source,
            cancel: Arc::new(AtomicBool::new(false)),
            allow_public_registries: true,
        };
        assert!(transport
            .validate_destination(&destination(source, "github.com"))
            .is_ok());
        assert!(transport
            .validate_destination(&destination(
                "https://release-assets.githubusercontent.com/pinned?opaque=1",
                "release-assets.githubusercontent.com"
            ))
            .is_ok());
        for (url, host) in [
            (
                "https://github.com/astral-sh/other/releases/download/x",
                "github.com",
            ),
            (
                "https://github.com/hashgraph-online/hol-cigar/releases/download/x",
                "github.com",
            ),
            ("https://example.com/x", "example.com"),
            (
                "https://release-assets.githubusercontent.com.attacker.example/x",
                "release-assets.githubusercontent.com.attacker.example",
            ),
        ] {
            assert!(transport
                .validate_destination(&destination(url, host))
                .is_err());
        }
    }
    #[test]
    fn dependency_url_must_match_exactly_and_honor_registry_policy() {
        let source = "https://files.pythonhosted.org/packages/pinned.whl";
        let transport = Transport {
            source,
            cancel: Arc::new(AtomicBool::new(false)),
            allow_public_registries: false,
        };
        assert_eq!(
            transport
                .validate_destination(&destination(source, "files.pythonhosted.org"))
                .unwrap_err()
                .code,
            "managed_public_registry_disabled"
        );
        let transport = Transport {
            allow_public_registries: true,
            ..transport
        };
        assert!(transport
            .validate_destination(&destination(source, "files.pythonhosted.org"))
            .is_ok());
        assert!(transport
            .validate_destination(&destination(
                "https://files.pythonhosted.org/other.whl",
                "files.pythonhosted.org"
            ))
            .is_err());
        assert!(transport
            .validate_destination(&destination(
                "https://release-assets.githubusercontent.com/x",
                "release-assets.githubusercontent.com"
            ))
            .is_err());
    }
}
