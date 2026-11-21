//! Wire request for planning a native hook package review.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Plan the settle of a native package review.
///
/// The caller forwards the hook payload as the daemon recorded it, with the
/// stamped execution environment. The runtime reads the command (including
/// Copilot's `toolArgs`), checks it is one plain JS package-manager command,
/// parses its install or exec intent, proves the npm a plain npm install runs,
/// and answers with the request artifact the package evaluator reads and
/// whether the evaluator's verdict may let the command continue. Without that
/// proof only a block verdict applies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageReviewPlanRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub guard_home: String,
    /// Absolute workspace directory the command runs in.
    pub workspace: String,
    pub harness: String,
    /// The hook payload, forwarded unchanged.
    pub payload: Value,
    #[serde(default)]
    pub home_dir: Option<String>,
    /// The native review's reason code. A command review, which the edge
    /// gives an `npx` or `bunx` launch, is planned only for those launchers
    /// and only a block verdict applies to it. Absent means a package review.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_reason: Option<String>,
    /// Return a pre-rendered retry when the plan can settle an install.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_registry_retry: Option<bool>,
}
