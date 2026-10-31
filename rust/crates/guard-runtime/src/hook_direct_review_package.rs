//! The package reviews the daemon queues without trying to settle them.
//!
//! Before it queues a review, `pause_native_pre_tool_for_approval`
//! (`hook_native_review_approval.py`) asks `native_package_review_response`
//! (`hook_native_package_review.py`) to settle a package review. That step
//! plans the settle through the resident's `package_review_plan` op, which
//! reads the command and its shape exactly as this check does, and hands any
//! JS package-manager install or exec to the package evaluator.
//!
//! When the plan has no command to evaluate, the daemon queues the review as
//! it queues any other, and so may the resident. A review that reaches the
//! evaluator stays with the daemon.

use crate::package_review_plan_op::{planned_shape, settles};
use guard_command::hook_responses::Object;
use serde_json::{Map, Value};

#[cfg(test)]
pub(super) use crate::package_review_plan_op::{LAUNCH_REVIEW_REASON, PACKAGE_REVIEW_REASON};

/// Whether `native_package_review_response` returns `None` for this review
/// without asking the package evaluator, so the daemon goes on to queue it.
///
/// `payload` is the payload as the daemon records it. The resident always has
/// a workspace, so that check never returns `None` here. `false` means the
/// daemon may settle the review.
pub(super) fn left_to_queue(payload: &Map<String, Value>, result: &Object) -> bool {
    !settles(result)
        || planned_shape(payload, result.get("reason_code").and_then(Value::as_str)).is_none()
}

#[cfg(test)]
#[path = "hook_direct_review_package_tests.rs"]
mod tests;
