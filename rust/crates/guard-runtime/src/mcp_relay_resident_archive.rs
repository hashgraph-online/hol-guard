//! The external-archive binding of a claimed package call.
//!
//! Port of `_bound_external_archive_mcp_request` (`runtime_mcp.py:98`) for the
//! relay. The evaluation the relay runs after a claim may download and verify
//! external tarballs. A call whose evaluation did so is only forwarded once its
//! request names the verified local blobs instead of the source URLs the child
//! would fetch again. The relay re-verifies every blob, rewrites the request,
//! and tells the resident whether the binding held, so a call it cannot bind is
//! answered with the terminal `mcp_unbound` block. The blobs stay on disk until
//! the child has answered the forwarded call.

use guard_command::local_supply_chain::{
    package_evaluation_requires_external_archive_binding, PackageRequestEvaluation,
};
use guard_command::restricted_archive::RestrictedArchiveDownload;
use guard_contracts::McpExternalArchiveDownloadV1;
use serde_json::{Map, Value};

use crate::mcp_proxy_archive::bind_replacements;
use crate::mcp_proxy_archive_verify::verified_replacements;

/// The verified blobs one evaluation retained. Every blob is removed when this
/// is dropped (`_cleanup_external_archive_downloads`).
#[derive(Debug, Default)]
pub(super) struct Retained(Vec<RestrictedArchiveDownload>);

impl Retained {
    pub(super) fn new(downloads: Vec<RestrictedArchiveDownload>) -> Self {
        Self(downloads)
    }

    fn downloads(&self) -> Vec<McpExternalArchiveDownloadV1> {
        self.0
            .iter()
            .map(|download| McpExternalArchiveDownloadV1 {
                source_url: download.source_url.clone(),
                path: download.path.to_string_lossy().into_owned(),
                size: download.size,
                sha256: download.sha256.clone(),
            })
            .collect()
    }
}

impl Drop for Retained {
    fn drop(&mut self) {
        for download in &self.0 {
            download.cleanup();
        }
    }
}

impl super::ResidentRelayAuthority {
    /// Remove the blobs the call with this evidence ticket was bound to.
    pub(super) fn release_archives(&mut self, evidence: Option<&str>) {
        if let Some(evidence) = evidence {
            self.archives.retain(|(held, _)| held != evidence);
        }
    }
}

/// What the binding made of one call's request.
#[derive(Debug, PartialEq)]
pub(super) enum Binding {
    /// No archive was retained and none is required: forward as received.
    Unchanged,
    /// The request params rewritten to name the verified blobs.
    Bound(Value),
    /// The call cannot be bound and must not be forwarded.
    Unbound,
}

impl Binding {
    /// The `external_archive_bound` fact the claim carries: `None` when the
    /// request was left as received.
    pub(super) fn bound(&self) -> Option<bool> {
        match self {
            Self::Unchanged => None,
            Self::Bound(_) => Some(true),
            Self::Unbound => Some(false),
        }
    }
}

/// Bind `params` to the blobs `retained` holds, re-verifying each first.
pub(super) fn bind(
    params: &Value,
    evaluation: &Map<String, Value>,
    retained: &Retained,
) -> Binding {
    let requires = package_evaluation_requires_external_archive_binding(
        &PackageRequestEvaluation::new(Value::Object(evaluation.clone())),
    );
    if retained.0.is_empty() {
        return if requires {
            Binding::Unbound
        } else {
            Binding::Unchanged
        };
    }
    let Some(replacements) = verified_replacements(&retained.downloads()) else {
        return Binding::Unbound;
    };
    let answer = bind_replacements(params, &replacements, requires);
    match answer.get("kind").and_then(Value::as_str) {
        Some("unchanged") => Binding::Unchanged,
        Some("bound") => {
            let mut bound = params.clone();
            let edits = answer.get("edits").and_then(Value::as_array);
            match edits.and_then(|edits| apply(&mut bound, edits)) {
                Some(()) => Binding::Bound(bound),
                None => Binding::Unbound,
            }
        }
        _ => Binding::Unbound,
    }
}

/// Apply `{path, value}` edits, where each path step is an object key or an
/// array index from the params root. An edit that names no node refuses.
fn apply(params: &mut Value, edits: &[Value]) -> Option<()> {
    for edit in edits {
        let path = edit.get("path")?.as_array()?;
        let value = edit.get("value")?.clone();
        let mut node = &mut *params;
        for step in path {
            node = match step {
                Value::String(key) => node.get_mut(key.as_str())?,
                Value::Number(index) => node.get_mut(usize::try_from(index.as_u64()?).ok()?)?,
                _ => return None,
            };
        }
        *node = value;
    }
    Some(())
}

#[cfg(test)]
#[path = "mcp_relay_resident_archive_tests.rs"]
mod tests;
