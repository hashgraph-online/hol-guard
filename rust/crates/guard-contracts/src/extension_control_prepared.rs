//! `ExtensionControl` prepared-candidate queries — wire contract for what the
//! daemon binds around an Extension control commit that was prepared in advance.
//!
//! A preview that needs approval is remembered by the digest of the request it
//! answered, and the apply must repeat exactly that request (`request_digest`).
//! A prepared enable candidate stages immutable activation records, and the
//! mutation the approval proves is bound to them through a derived nonce
//! (`candidate_nonce`). The audit event of a committed mutation names each
//! changed target by an opaque reference and the rules it affects
//! (`preview_event_targets`). The daemon asks; the resident decides how each is
//! computed.

use serde::{Deserialize, Serialize};

/// Most changed targets one audit event names.
pub const EXTENSION_CONTROL_MAX_EVENT_TARGETS: usize = 512;
/// Most affected rule ids one audit event names for a target.
pub const EXTENSION_CONTROL_MAX_EVENT_RULE_IDS: usize = 1_024;

/// One changed target as the audit event records it. The target id is not
/// recorded, only `target_ref`, a digest that names it without disclosing it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlEventTargetV1 {
    /// `extension` or `permission`.
    pub kind: String,
    /// Lowercase hex SHA-256 of the target's kind and id.
    pub target_ref: String,
    pub before_explicit: String,
    pub after_explicit: String,
    pub before_effective: String,
    pub after_effective: String,
    /// The rules the target alone changes, in preview order.
    pub affected_rule_ids: Vec<String>,
}
