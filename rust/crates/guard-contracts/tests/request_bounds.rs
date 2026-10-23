//! Every size a contract bounds stays under one resident frame.
//!
//! [`MAX_NATIVE_REQUEST_BYTES`] is enforced by the transport on a frame's body
//! before any op sees it, so a bound at or above it is unreachable: a request
//! between the two is refused as a malformed frame rather than for its own
//! size, and the caller is told the runtime is broken rather than that it asked
//! for too much. The same holds for a bound on one field of a request, which
//! cannot be reached without the request reaching it first.
//!
//! The bounds here count a canonical serialization and the transport counts the
//! sender's own, so equality is not enough either: a bound needs room for the
//! two to differ, which is why the ops nearest the limit sit a frame's slack
//! below it.
//!
//! `ARCHIVE_ACQUISITION_MAX_BYTES` is deliberately absent. It bounds an archive
//! Guard downloads, not anything that travels in a request, so the frame limit
//! says nothing about it.

use std::fs;
use std::path::Path;

use guard_contracts::MAX_NATIVE_REQUEST_BYTES;

/// Pins one bound at compile time, naming it in the failure.
macro_rules! under_one_frame {
    ($($bound:ident),+ $(,)?) => {
        $(
            const {
                assert!(
                    guard_contracts::$bound < MAX_NATIVE_REQUEST_BYTES,
                    concat!(
                        stringify!($bound),
                        " is not under MAX_NATIVE_REQUEST_BYTES, so a request that \
                         reaches it is refused as a malformed frame instead of for \
                         its size",
                    ),
                )
            };
        )+
    };
}

#[test]
fn every_declared_bound_fits_one_resident_frame() {
    under_one_frame!(
        AIBOM_REPORT_SUMMARIES_MAX_REQUEST_BYTES,
        APPROVAL_BULK_ELIGIBILITY_MAX_BYTES,
        APPROVAL_CONTEXT_TOKEN_MAX_BYTES,
        APPROVAL_EXTENSION_RECOMMENDATION_MAX_BYTES,
        APPROVAL_GATE_MAX_BYTES,
        APPROVAL_PERSIST_SELECT_MAX_BYTES,
        APPROVAL_QUEUE_IDENTITY_MAX_BYTES,
        APPROVAL_RESOLUTION_ELIGIBILITY_MAX_BYTES,
        APPROVAL_RESOLUTION_PLAN_MAX_BYTES,
        APPROVAL_REUSE_MAX_BYTES,
        APPROVAL_SCOPE_MAX_BYTES,
        APPROVAL_SCOPE_SELECT_MAX_BYTES,
        ARCHIVE_ACQUISITION_MAX_REQUEST_BYTES,
        ARTIFACT_CONTENT_HASH_MAX_BYTES,
        CISCO_PREFLIGHT_MAX_BYTES,
        CLAIM_APPROVAL_REUSE_MAX_BYTES,
        CODEX_HOOK_IDENTITY_MAX_BYTES,
        CODEX_POST_TOOL_OUTPUT_MAX_BYTES,
        CODEX_REQUEST_RESUME_MAX_BYTES,
        CODEX_TOOL_OUTPUT_MAX_BYTES,
        COMMAND_EFFECT_BATCH_MAX_BYTES,
        COMMAND_EFFECT_MAX_BYTES,
        COMMAND_POLICY_DECISION_MAX_BYTES,
        COMPOSIO_ROLE_MAX_BYTES,
        COMPOUND_GIT_INSPECTION_MAX_BYTES,
        CONTEXT_COMPONENT_MAX_BYTES,
        CURSOR_OBSERVER_PROOF_MAX_BYTES,
        DAEMON_HANDLER_MAX_BYTES,
        DAEMON_LIFECYCLE_MAX_BYTES,
        DAEMON_ROUTE_MAX_BYTES,
        EXTENSION_ALLOW_HINT_MAX_BYTES,
        EXTENSION_CONTROL_AUTHORITY_MAX_BYTES,
        EXTENSION_CONTROL_MAX_BYTES,
        GITHUB_CLI_CLASSIFY_MAX_BYTES,
        GITHUB_WORKFLOW_PREPARE_MAX_BYTES,
        GIT_EXECUTION_SAFETY_MAX_BYTES,
        GUARD_STORE_MAX_REQUEST_BYTES,
        HOOK_ARTIFACT_FACTS_MAX_BYTES,
        HOOK_AUTHORITY_STATE_MAX_BYTES,
        HOOK_RENDER_MAX_BYTES,
        INVENTORY_ITEM_CLASSIFICATION_MAX_BYTES,
        INVENTORY_SCAN_FINDINGS_MAX_BYTES,
        INVENTORY_SCAN_TARGETS_MAX_BYTES,
        INVENTORY_SNAPSHOT_DIGEST_MAX_BYTES,
        INVENTORY_SOURCE_EVIDENCE_MAX_BYTES,
        INVENTORY_URL_REDACTION_MAX_REQUEST_BYTES,
        MCP_CLASSIFICATION_MAX_BYTES,
        MCP_PROXY_DECISION_MAX_BYTES,
        MCP_RUNTIME_EVIDENCE_MAX_BYTES,
        MCP_TOOL_CALL_IDENTITY_MAX_BYTES,
        MCP_TOOL_EVIDENCE_MAX_BYTES,
        MCP_TOOL_POLICY_DECIDE_MAX_BYTES,
        NATIVE_APPROVAL_MAX_BYTES,
        NATIVE_APPROVAL_RESPONSE_MAX_BYTES,
        NATIVE_BASH_LAUNCH_MAX_REQUEST_BYTES,
        NATIVE_BUSINESS_DISPATCH_RECEIPT_MAX_BYTES,
        NATIVE_EXACT_ACTION_MAX_BYTES,
        NATIVE_HOOK_DECISION_RECEIPT_MAX_BYTES,
        PACKAGE_AUDIT_PROJECTION_MAX_BYTES,
        PACKAGE_AUTHORITY_MAX_BYTES,
        PACKAGE_CONTEXT_BUILD_MAX_BYTES,
        PACKAGE_EVALUATION_VIEW_MAX_REQUEST_BYTES,
        POLICY_BUNDLE_AUTHORITY_MAX_BYTES,
        POLICY_DECISION_LOOKUP_MAX_BYTES,
        POLICY_DOCUMENT_DECISION_MAX_BYTES,
        POLICY_INTEGRITY_ROWS_MAX_BYTES,
        PROTECT_REQUEST_MAX_BYTES,
        REVIEWED_INVOCATION_BINDINGS_MAX_BYTES,
        RUNNER_AUTHORITY_MAX_BYTES,
        RUNTIME_ARTIFACT_IDENTITY_MAX_REQUEST_BYTES,
        RUNTIME_DETECTOR_RUN_MAX_BYTES,
        SHIM_ADMIN_MAX_BYTES,
        SKILL_WORKFLOW_PREFLIGHT_MAX_BYTES,
        TOOL_ACTION_REQUEST_IDENTITY_MAX_REQUEST_BYTES,
        VERIFIED_READ_DECISION_MAX_REQUEST_BYTES,
        VERIFIED_READ_PLAN_MAX_REQUEST_BYTES,
    );
}

/// A bound the list above forgot is a bound nothing holds under the frame
/// limit, and the whole point of the list is that none is missed. Read the
/// declarations back out of the crate's own source and require each one to be
/// named here.
#[test]
fn every_declared_bound_is_named_above() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let pinned = include_str!("request_bounds.rs");
    let mut found = 0usize;
    for entry in fs::read_dir(&source).expect("contract sources") {
        let path = entry.expect("source entry").path();
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("contract source");
        for declaration in text.lines().filter_map(declared_bound) {
            assert!(
                pinned.contains(&format!("\n        {declaration},\n")),
                "{declaration} is declared in {} but is not pinned in this test",
                path.display(),
            );
            found += 1;
        }
    }
    assert!(found > 0, "no bounds were read out of {}", source.display());
}

/// The name a line declares as a public byte bound, if it declares one.
///
/// `usize` is what the ops measure a request in. A bound in another type, such
/// as the `u64` an archive's size is read as, is not something a request
/// carries and the frame limit says nothing about it.
///
/// An op names its bound either way round -- `..._MAX_BYTES` or
/// `..._MAX_REQUEST_BYTES` -- and both count the same thing, so reading only
/// the first shape left the ops that chose the second unpinned. The frame limit
/// itself is `MAX_NATIVE_REQUEST_BYTES`, which matches neither suffix, so it is
/// still not asked to fit under itself.
fn declared_bound(line: &str) -> Option<&str> {
    let name = line.strip_prefix("pub const ")?.split_once(": usize = ")?.0;
    (name.ends_with("_MAX_BYTES") || name.ends_with("_MAX_REQUEST_BYTES")).then_some(name)
}
