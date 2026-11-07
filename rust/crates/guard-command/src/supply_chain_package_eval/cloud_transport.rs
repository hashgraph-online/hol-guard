use super::*;

/// Code and message for a 403 at Guard Cloud's address. Cloudflare in front of
/// Guard Cloud answers its own 403 when it blocks or challenges a client; that is
/// a network failure, not an expired sign-in, so it must not ask for a reconnect.
pub(super) fn cloud_403_reason(edge_block_reason: Option<&str>) -> (&'static str, String) {
    match edge_block_reason {
        Some(reason) => (
            "cloud_http_error",
            format!(
                "{reason} Guard blocked the install rather than bypassing Cloud package protection."
            ),
        ),
        None => (
            "cloud_auth_error",
            "Guard cloud evaluation was not authorized, so this package request needs review."
                .to_owned(),
        ),
    }
}

/// Which decision a Guard Cloud reply that rejected the evaluation request
/// itself (HTTP 400 or 404) deserves.
///
/// Those two statuses mean Cloud never read the package as a package: it
/// refused the request or had no endpoint for it, so there is no advisory, no
/// feed match and no verdict behind the answer. Ending the install with
/// `block` presents that unavailability as a supply-chain finding and leaves
/// no approval request behind, so the user has no way through at all — a
/// locally built wheel, which Cloud cannot have a record of, can then never be
/// installed on a machine where Guard enforces.
///
/// An unvalidatable request still stops the install, but through the approval
/// queue, where the review keeps Allow once and Always allow. The workspace's
/// own fail-closed decision still wins when it is `block` (the `strict` and
/// `paranoid` security levels, or a `cloud_advisory` risk action set to
/// block), so a workspace that asked for a hard floor keeps one.
///
/// This is what the evaluator already does with the sibling failures that
/// carry no verdict either: a cloud timeout and a credential or network
/// failure both route to `ask` rather than to `block`.
pub(super) fn cloud_no_verdict_decision(
    failure_decision: &str,
    configured_fail_closed: &str,
) -> String {
    if failure_decision == "block" && configured_fail_closed != "block" {
        return "ask".to_string();
    }
    failure_decision.to_string()
}

/// The sentence that tells the user what Guard did with a request Cloud could
/// not validate. It has to follow the decision actually recorded: a `block`
/// ends the install, an `ask` stops it at the approval queue.
fn no_verdict_outcome_sentence(decision: &str) -> &'static str {
    if decision == "block" {
        "Guard blocked the install rather than bypassing Cloud package protection."
    } else {
        "Guard paused the install for explicit review rather than bypassing Cloud package protection."
    }
}

/// The reason code, user message and recorded decision for one HTTP status on
/// the evaluate endpoint. `None` means Guard records no cloud failure and
/// continues with local intelligence instead.
pub(super) fn cloud_http_failure_outcome(
    status_code: u16,
    edge_block_reason: Option<&str>,
    fail_closed_decision: &str,
    configured_fail_closed: &str,
) -> Option<(&'static str, String, String)> {
    if status_code == 403 {
        let (code, message) = cloud_403_reason(edge_block_reason);
        return Some((code, message, fail_closed_decision.to_string()));
    }
    if fail_closed_decision != "block" {
        return None;
    }
    match status_code {
        401 => Some((
            "cloud_auth_error",
            "Guard Cloud could not authorize this package check. Guard blocked the install rather than bypassing Cloud package protection.".to_string(),
            fail_closed_decision.to_string(),
        )),
        400 | 404 => {
            let decision = cloud_no_verdict_decision(fail_closed_decision, configured_fail_closed);
            let outcome = no_verdict_outcome_sentence(&decision);
            Some((
                "cloud_validation_error",
                format!("Guard Cloud could not validate this package request. {outcome}"),
                decision,
            ))
        }
        _ => Some((
            "cloud_http_error",
            format!(
                "Guard Cloud returned HTTP {status_code} while verifying this package. Guard blocked the install rather than bypassing Cloud package protection."
            ),
            fail_closed_decision.to_string(),
        )),
    }
}

/// `_cloud_http_fail_closed_evaluation` (:1543-1595) — full form producing a
/// finalized `PackageEvalResult` (or `None` when `fail_closed_decision` is not
/// `block` and status is not 403).
#[allow(clippy::too_many_arguments)]
pub(super) fn cloud_http_fail_closed_evaluation_full(
    deps: &SupplyChainEvalDeps<'_>,
    status_code: u16,
    edge_block_reason: Option<&str>,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
    workspace_fingerprint: Option<&str>,
    bundle_meta: Option<&BTreeMap<String, String>>,
    fail_closed_decision: &str,
    configured_fail_closed: &str,
) -> Option<PackageEvalResult> {
    let (code, message, decision) = cloud_http_failure_outcome(
        status_code,
        edge_block_reason,
        fail_closed_decision,
        configured_fail_closed,
    )?;
    Some(cloud_fail_closed_evaluation_full(
        deps,
        code,
        &message,
        artifact,
        targets,
        workspace_dir,
        workspace_fingerprint,
        bundle_meta,
        &decision,
    ))
}

#[cfg(test)]
mod tests {
    use super::{cloud_403_reason, cloud_http_failure_outcome, cloud_no_verdict_decision};

    const BLOCKED: &str =
        "Guard blocked the install rather than bypassing Cloud package protection.";

    #[test]
    fn an_edge_block_403_is_a_network_failure_not_a_sign_in_problem() {
        let edge = "Guard Cloud is unreachable from this network: Cloudflare in front of Guard Cloud challenged the request (HTTP 403).";
        let (code, message) = cloud_403_reason(Some(edge));
        assert_eq!(code, "cloud_http_error");
        assert!(message.starts_with(edge), "{message}");
        assert!(!message.contains("not authorized"), "{message}");
        let (code, message) = cloud_403_reason(None);
        assert_eq!(code, "cloud_auth_error");
        assert!(message.contains("not authorized"), "{message}");
    }

    /// Regression: Guard Cloud answering the evaluate endpoint with 400 or 404
    /// means it refused the request and never scored the package. On an
    /// entitled workspace the evaluator's failure decision is always `block`,
    /// so every such reply used to end the install with `block` — a decision
    /// that files no approval request and leaves the user no way through, for
    /// an install Cloud never actually judged. A locally built release
    /// candidate wheel, which Cloud cannot have a record of, could therefore
    /// never be installed on a machine where Guard enforces.
    ///
    /// An unvalidatable request must stop at the approval queue instead, so
    /// the review keeps Allow once and Always allow, and the copy must say
    /// Guard paused rather than claim a block it did not make.
    ///
    /// The surrounding path (`CloudContext::http_status_outcome`) needs a full
    /// `SupplyChainEvalDeps` to drive end to end, so the decision ladder is
    /// pinned here, at the one place that owns it.
    #[test]
    fn a_request_cloud_could_not_validate_keeps_an_approval_path() {
        for status in [400, 404] {
            let (code, message, decision) =
                cloud_http_failure_outcome(status, None, "block", "ask")
                    .expect("an entitled workspace records the cloud failure");
            assert_eq!(code, "cloud_validation_error");
            assert_eq!(
                decision, "ask",
                "HTTP {status} is Cloud refusing the request, not a package verdict"
            );
            assert!(
                message.starts_with("Guard Cloud could not validate this package request."),
                "{message}"
            );
            assert!(
                message.contains("paused the install for explicit review"),
                "HTTP {status} copy must match the decision it recorded: {message}"
            );
            assert!(
                !message.contains("Guard blocked the install"),
                "HTTP {status} copy must not claim a block it did not make: {message}"
            );
        }
    }

    #[test]
    fn a_configured_block_floor_still_blocks_a_request_cloud_could_not_validate() {
        for status in [400, 404] {
            let (code, message, decision) =
                cloud_http_failure_outcome(status, None, "block", "block")
                    .expect("an entitled workspace records the cloud failure");
            assert_eq!(code, "cloud_validation_error");
            assert_eq!(
                decision, "block",
                "a strict or paranoid workspace keeps its hard floor on HTTP {status}"
            );
            assert!(message.ends_with(BLOCKED), "{message}");
        }
    }

    /// The other statuses are unchanged: they are covered by the recorded
    /// cloud vectors in `tests/fixtures/supply-chain-eval/cloud-cases.v1.json`
    /// and must keep producing exactly what those vectors hold.
    #[test]
    fn the_other_statuses_keep_their_recorded_outcome() {
        for status in [401, 422, 500] {
            let (_, message, decision) = cloud_http_failure_outcome(status, None, "block", "ask")
                .expect("an entitled workspace records the cloud failure");
            assert_eq!(decision, "block", "HTTP {status}");
            assert!(message.ends_with(BLOCKED), "{message}");
        }
        let (code, _, decision) = cloud_http_failure_outcome(403, None, "block", "ask")
            .expect("a 403 is answered by the edge and is always recorded");
        assert_eq!(code, "cloud_auth_error");
        assert_eq!(decision, "block");
    }

    #[test]
    fn an_unentitled_workspace_still_falls_back_to_local_intelligence() {
        for status in [400, 401, 404, 422, 500] {
            assert!(
                cloud_http_failure_outcome(status, None, "ask", "ask").is_none(),
                "HTTP {status} must still fall back to local intelligence"
            );
        }
        assert_eq!(cloud_no_verdict_decision("ask", "ask"), "ask");
    }
}
