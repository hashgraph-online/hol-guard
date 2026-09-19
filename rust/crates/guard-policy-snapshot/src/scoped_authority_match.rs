//! Match already-derived request identities against authenticated authority.
//!
//! This module validates bounds, not the provenance of request facts. The
//! native classifier must derive them from the actual action before calling
//! this API. No request type here can be deserialized from a hook payload.

use super::{
    integer, text, AuthorityError, NativePolicyAuthority, PolicyAction, PolicyScope,
    ScopedPolicyRow,
};
use std::cmp::Ordering;
use std::fmt;

const CONTEXT_PREFIX: &str = "guard-approval-context:v1:";

/// Exact bindings computed by the native identity producer, never caller labels.
#[derive(Default)]
pub struct ExactPolicyContextInputs<'a> {
    pub artifact_legacy: Option<&'a str>,
    pub runtime: Option<&'a str>,
    pub portable: Option<&'a str>,
    pub global: Option<&'a str>,
    pub approval: Option<&'a str>,
}

/// Inputs from one native-classified action. They create no authority or ACK.
pub struct PolicyIdentityInputs<'a> {
    pub harness: &'a str,
    pub artifact_id: Option<&'a str>,
    pub artifact_hash: Option<&'a str>,
    pub workspace: Option<&'a str>,
    pub publisher: Option<&'a str>,
    pub exact_command_sha256: Option<&'a str>,
    pub exact: ExactPolicyContextInputs<'a>,
}

pub struct ScopedPolicyRequest {
    harness: String,
    artifact_id: Option<String>,
    artifact_family: Option<String>,
    artifact_hash: Option<String>,
    workspace: Option<String>,
    workspace_key: Option<String>,
    publisher: Option<String>,
    exact_command_sha256: Option<String>,
    runtime_exact: Option<String>,
    global_exact: Option<String>,
    exact_contexts: Vec<String>,
}

impl fmt::Debug for ScopedPolicyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScopedPolicyRequest { .. }")
    }
}

impl ScopedPolicyRequest {
    pub fn artifact_id(&self) -> Option<&str> {
        self.artifact_id.as_deref()
    }

    pub fn from_native_identity(inputs: PolicyIdentityInputs<'_>) -> Result<Self, AuthorityError> {
        text(inputs.harness)?;
        if inputs
            .exact_command_sha256
            .is_some_and(|digest| !crate::valid_hex(digest, 64))
        {
            return Err(AuthorityError::ExactCommand);
        }
        for value in [
            inputs.artifact_id,
            inputs.artifact_hash,
            inputs.workspace,
            inputs.publisher,
            inputs.exact.artifact_legacy,
            inputs.exact.runtime,
            inputs.exact.portable,
            inputs.exact.global,
            inputs.exact.approval,
        ]
        .into_iter()
        .flatten()
        {
            text(value)?;
        }
        for key in [
            inputs.exact.artifact_legacy,
            inputs.exact.runtime,
            inputs.exact.portable,
            inputs.exact.global,
        ]
        .into_iter()
        .flatten()
        {
            if !key
                .strip_prefix("runtime-exact:")
                .is_some_and(|digest| crate::valid_hex(digest, 64))
            {
                return Err(AuthorityError::ExactContext);
            }
        }
        if inputs.exact.approval.is_some_and(|key| {
            Some(key) != inputs.artifact_hash || !key.starts_with(CONTEXT_PREFIX)
        }) || (inputs.artifact_hash.is_none()
            && [
                inputs.exact.runtime,
                inputs.exact.portable,
                inputs.exact.global,
            ]
            .into_iter()
            .any(|key| key.is_some()))
        {
            return Err(AuthorityError::ExactContext);
        }
        let mut exact_contexts = Vec::new();
        for key in [
            inputs.exact.artifact_legacy,
            inputs.exact.runtime,
            inputs.exact.portable,
            inputs.exact.global,
            inputs.exact.approval,
        ]
        .into_iter()
        .flatten()
        {
            if !exact_contexts.iter().any(|previous| previous == key) {
                exact_contexts.push(key.to_owned());
            }
        }
        Ok(Self {
            harness: inputs.harness.to_owned(),
            artifact_id: inputs.artifact_id.map(str::to_owned),
            artifact_family: inputs.artifact_id.and_then(artifact_family),
            artifact_hash: inputs.artifact_hash.map(str::to_owned),
            workspace: inputs.workspace.map(str::to_owned),
            workspace_key: inputs.workspace.map(workspace_key),
            publisher: inputs.publisher.map(str::to_owned),
            exact_command_sha256: inputs.exact_command_sha256.map(str::to_owned),
            runtime_exact: inputs.exact.runtime.map(str::to_owned),
            global_exact: inputs.exact.global.map(str::to_owned),
            exact_contexts,
        })
    }
}

fn artifact_family(artifact: &str) -> Option<String> {
    let family = if let Some(family) = artifact.strip_prefix("family:") {
        family
    } else {
        artifact.split(':').nth(2)?
    };
    let normalized = family.trim().to_lowercase();
    if !matches!(
        normalized.as_str(),
        "file-read"
            | "mcp"
            | "mcp-tool"
            | "package-request"
            | "prompt"
            | "prompt-env-read"
            | "prompt-file"
            | "tool-action"
    ) {
        return None;
    }
    Some(if artifact.starts_with("family:") {
        artifact.to_owned()
    } else {
        format!("family:{normalized}")
    })
}

fn workspace_key(workspace: &str) -> String {
    let mut normalized = workspace.trim().replace('\\', "/");
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    if normalized.chars().nth(1) == Some(':') {
        normalized = normalized.to_lowercase();
    }
    format!("workspace:{}", crate::digest_bytes(normalized.as_bytes()))
}

fn equal_present(left: Option<&str>, right: Option<&str>) -> bool {
    left.is_some() && left == right
}

fn hash_matches(
    row: &ScopedPolicyRow,
    request: &ScopedPolicyRequest,
    exact: Option<&str>,
    legacy: bool,
) -> bool {
    let Some(digest) = row.artifact_hash.as_deref() else {
        return true;
    };
    Some(digest) == request.artifact_hash.as_deref()
        || Some(digest) == exact
        || (legacy
            && !digest
                .get(..CONTEXT_PREFIX.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(CONTEXT_PREFIX)))
}

pub(super) fn matches_row(
    row: &ScopedPolicyRow,
    request: &ScopedPolicyRequest,
    now_ms: u64,
) -> bool {
    if (row.harness != "*" && row.harness != request.harness)
        || row.expires_at_ms.is_some_and(|expiry| expiry <= now_ms)
        || row
            .exact_command_sha256
            .as_ref()
            .is_some_and(|digest| request.exact_command_sha256.as_ref() != Some(digest))
    {
        return false;
    }
    let artifact = row.artifact_id.as_deref();
    let family_or_broad =
        artifact.is_none() || equal_present(artifact, request.artifact_family.as_deref());
    let matched = match row.scope {
        PolicyScope::Artifact => {
            equal_present(artifact, request.artifact_id.as_deref())
                && hash_matches(row, request, request.runtime_exact.as_deref(), false)
        }
        PolicyScope::Workspace => {
            (equal_present(row.workspace.as_deref(), request.workspace_key.as_deref())
                || equal_present(row.workspace.as_deref(), request.workspace.as_deref()))
                && (family_or_broad || equal_present(artifact, request.artifact_id.as_deref()))
                && hash_matches(row, request, None, false)
        }
        PolicyScope::Publisher => {
            equal_present(row.publisher.as_deref(), request.publisher.as_deref())
                && hash_matches(row, request, None, true)
        }
        PolicyScope::Harness => {
            family_or_broad && hash_matches(row, request, request.runtime_exact.as_deref(), true)
        }
        PolicyScope::Global => {
            family_or_broad && hash_matches(row, request, request.global_exact.as_deref(), true)
        }
    };
    matched
        && (!row.requires_exact_context
            || row
                .artifact_hash
                .as_ref()
                .is_some_and(|digest| request.exact_contexts.contains(digest)))
}

fn scope_rank(scope: PolicyScope) -> u8 {
    match scope {
        PolicyScope::Artifact => 4,
        PolicyScope::Workspace => 3,
        PolicyScope::Publisher => 2,
        PolicyScope::Harness => 1,
        PolicyScope::Global => 0,
    }
}

fn action_rank(action: PolicyAction) -> u8 {
    match action {
        PolicyAction::Allow => 0,
        PolicyAction::Warn => 1,
        PolicyAction::Review => 2,
        PolicyAction::RequireReapproval => 3,
        PolicyAction::SandboxRequired => 4,
        PolicyAction::Block => 5,
    }
}

fn compare_precedence(left: &ScopedPolicyRow, right: &ScopedPolicyRow) -> Ordering {
    let primary = |row: &ScopedPolicyRow| {
        (
            scope_rank(row.scope),
            matches!(
                row.scope,
                PolicyScope::Workspace | PolicyScope::Harness | PolicyScope::Global
            ) && row.artifact_id.is_some(),
            row.updated_at_us,
            action_rank(row.action),
        )
    };
    primary(left).cmp(&primary(right)).then_with(|| {
        (
            &left.harness,
            &left.artifact_id,
            &left.artifact_hash,
            &left.workspace,
            &left.publisher,
            &left.exact_command_sha256,
            left.expires_at_ms,
        )
            .cmp(&(
                &right.harness,
                &right.artifact_id,
                &right.artifact_hash,
                &right.workspace,
                &right.publisher,
                &right.exact_command_sha256,
                right.expires_at_ms,
            ))
    })
}

impl NativePolicyAuthority {
    /// Select generic authority only. Independent native and managed floors
    /// must still be composed by the resident consumer before execution.
    pub fn select_generic<'a>(
        &'a self,
        request: &ScopedPolicyRequest,
        now_ms: u64,
    ) -> Result<Option<&'a ScopedPolicyRow>, AuthorityError> {
        integer(now_ms, false)?;
        Ok(self
            .rows()
            .iter()
            .filter(|row| !self.has_command_expression(row.decision_id))
            .filter(|row| matches_row(row, request, now_ms))
            .max_by(|left, right| compare_precedence(left, right)))
    }
}

#[cfg(test)]
#[path = "scoped_authority_match_tests.rs"]
mod tests;
