//! `DaemonRoute` — wire contract for the resident daemon route-policy op.
//!
//! The daemon's HTTP framing stays in Python. Every authorization-relevant
//! decision between "a request arrived" and "the handler runs" is answered by
//! the resident: which routes need a header token, which routes a dashboard
//! session may reach, whether an `Origin` may call a path, whether a signed
//! session claim authorizes a request, and how an approval-resolution body is
//! validated. Every query is pure (no IO, no SQLite); a transport failure is
//! "no decision" and the caller must fail closed.

use serde::{Deserialize, Serialize};

/// Schema discriminator for the request.
pub const DAEMON_ROUTE_REQUEST_SCHEMA: &str = "guard-daemon-route-request.v1";
/// Schema discriminator for the result.
pub const DAEMON_ROUTE_RESULT_SCHEMA: &str = "guard-daemon-route-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const DAEMON_ROUTE_FEATURE: &str = "daemon-route-v1";
/// Largest canonical request serialization the op will accept.
pub const DAEMON_ROUTE_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonRouteRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub query: DaemonRouteQueryV1,
}

/// A text field as the transport saw it: absent, usable (already stripped) text,
/// or present with a non-text JSON type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum DaemonTextFieldV1 {
    Absent,
    Text { value: String },
    Invalid,
}

/// A string-list field: absent, a list whose items are all strings, or invalid.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum DaemonListFieldV1 {
    Absent,
    Strings { values: Vec<String> },
    Invalid,
}

/// Verified dashboard-session claims, each text value already stripped and
/// `None` when it was absent, non-text or blank.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonSessionClaimsV1 {
    #[serde(default)]
    pub surface: Option<String>,
    #[serde(default)]
    pub action_path: Option<String>,
    #[serde(default)]
    pub harness: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub workspace_id_camel: Option<String>,
    #[serde(default)]
    pub location_id: Option<String>,
    #[serde(default)]
    pub location_id_camel: Option<String>,
    #[serde(default)]
    pub daemon_origin: Option<String>,
    #[serde(default)]
    pub daemon_origin_camel: Option<String>,
    /// String items of the `allowed_read_paths` claim; `None` when not a list.
    #[serde(default)]
    pub allowed_read_paths: Option<Vec<String>>,
    /// String items of the `allowed_action_paths` claim; `None` when not a list.
    #[serde(default)]
    pub allowed_action_paths: Option<Vec<String>>,
    /// String items of the `managers` claim; `None` when not a list.
    #[serde(default)]
    pub managers: Option<Vec<String>>,
}

/// The request-body fields a claim may be compared against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonSessionPayloadV1 {
    #[serde(default)]
    pub harness: Option<String>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub workspace_id_camel: Option<String>,
    #[serde(default)]
    pub location_id: Option<String>,
    #[serde(default)]
    pub location_id_camel: Option<String>,
    #[serde(default)]
    pub daemon_origin: Option<String>,
    #[serde(default)]
    pub daemon_origin_camel: Option<String>,
    #[serde(default)]
    pub dashboard_session_nonce: Option<String>,
    pub managers: DaemonListFieldV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DaemonRouteQueryV1 {
    /// Static route facts for one method and URL path.
    Route { method: String, path: String },
    /// Whether a normalized `Origin` may call `path`.
    Origin { origin: String, path: String },
    /// Strict loopback-origin acceptance for a candidate origin.
    StrictLoopback {
        raw: String,
        #[serde(default)]
        normalized: Option<String>,
    },
    /// Whether verified session claims authorize one request.
    SessionAuthorize {
        method: String,
        path: String,
        claims: Box<DaemonSessionClaimsV1>,
        #[serde(default)]
        payload: Option<DaemonSessionPayloadV1>,
        #[serde(default)]
        header_nonce: Option<String>,
        #[serde(default)]
        request_origin: Option<String>,
    },
    /// Validation of an approval-resolution request.
    ResolveRequest {
        path: String,
        action: DaemonTextFieldV1,
        scope: DaemonTextFieldV1,
        scope_contract_version: DaemonTextFieldV1,
        scope_contract_digest: DaemonTextFieldV1,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DaemonRoutePayloadV1 {
    Route {
        requires_header_token: bool,
        session_path: bool,
        /// `extension_control`, `local_cli` or `none`.
        route_class: String,
    },
    Origin {
        allowed: bool,
        hosted_origin: bool,
    },
    StrictLoopback {
        origin: Option<String>,
    },
    SessionAuthorize {
        /// The verdict assuming `consume_nonce`, when set, is consumed once.
        allowed: bool,
        /// A single-use nonce the caller must consume before honoring `allowed`.
        consume_nonce: Option<String>,
    },
    ResolveRequest {
        /// `not_matched`, `missing_required_fields`,
        /// `invalid_scope_contract_version`, `invalid_scope_contract_digest`
        /// or `resolved`.
        outcome: String,
        request_id: Option<String>,
        action: Option<String>,
        scope: Option<String>,
        scope_contract_version: Option<String>,
        scope_contract_digest: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonRouteResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_daemon_route_*` failure codes.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<DaemonRoutePayloadV1>,
}
