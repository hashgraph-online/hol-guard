//! Brokered network egress for the resident's supply-chain evaluation.
//!
//! The resident never opens a socket for package evaluation. Every exchange it
//! needs (Guard Cloud, the OAuth token endpoint, public registries, external
//! archives) is described to the caller as an [`EgressNeedV1`]. The caller
//! performs it under its own managed network policy (destination allow-list,
//! policy proxy, CA bundle, proxy credentials) and repeats the request with
//! the outcome in `egress_supplied`. The resident still parses every response
//! and owns every decision; the caller only moves bytes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// `code` of an `ok` envelope that asks the caller to perform network
/// exchanges. The payload is [`EgressRequiredV1`], not a verdict.
pub const EGRESS_REQUIRED_CODE: &str = "supply_chain_egress_required";

/// Most supplied outcomes one request may carry.
pub const EGRESS_MAX_SUPPLIED: usize = 256;
/// Most needs one answer may carry.
pub const EGRESS_MAX_NEEDS: usize = 16;
/// Largest response body the caller may inline in the request; bigger bodies
/// are written to the spool directory and named in `body_file`.
pub const EGRESS_MAX_INLINE_BODY_BYTES: usize = 32 * 1024;
/// Largest request body the resident will hand to the caller to send.
pub const EGRESS_MAX_NEED_BODY_BYTES: usize = 512 * 1024;
/// Most response headers kept per outcome.
pub const EGRESS_MAX_HEADERS: usize = 64;

/// One exchange the resident needs performed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EgressNeedV1 {
    /// `oauth`, `cloud`, `registry` or `archive`.
    pub class: String,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Request body (UTF-8 text), absent for a bodiless request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Lowercase hex SHA-256 of the request body, empty when there is none.
    pub body_sha256: String,
    /// Which use of the same (class, method, url, body) this is, from 1.
    pub occurrence: u32,
    pub timeout_seconds: f64,
    /// Redirects the caller may follow; `0` means refuse every redirect.
    pub max_redirects: u32,
    /// Response body cap. For `archive` this is the archive size cap.
    pub max_response_bytes: u64,
    /// Seconds the caller waits before performing the exchange (a retry pause
    /// the resident would otherwise have slept).
    pub delay_seconds: f64,
}

/// Payload of an [`EGRESS_REQUIRED_CODE`] answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EgressRequiredV1 {
    pub needs: Vec<EgressNeedV1>,
}

/// The caller's result for one need, keyed by what it answers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EgressSuppliedV1 {
    pub class: String,
    pub method: String,
    pub url: String,
    pub body_sha256: String,
    pub occurrence: u32,
    pub outcome: EgressOutcomeV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EgressOutcomeV1 {
    /// An HTTP exchange completed with this status (any status, 2xx or not).
    Response {
        status: u16,
        #[serde(default)]
        headers: BTreeMap<String, String>,
        /// UTF-8 body inline, for small responses.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        body: Option<String>,
        /// Plain file name, inside the request's spool directory, holding the
        /// body bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        body_file: Option<String>,
    },
    /// The exchange timed out.
    Timeout,
    /// The exchange failed before a response (DNS, TLS, connect, read).
    Error { message: String },
    /// The caller's managed network policy refused the destination.
    Blocked { code: String },
    /// An external archive was downloaded and verified by the caller.
    Archive {
        sha256: String,
        size: u64,
        final_url: String,
    },
    /// An external archive download was refused or failed.
    ArchiveFailure { code: String, message: String },
}
