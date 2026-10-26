//! Signed policy-bundle validation and typed authority operations.
//!
//! The runtime owns transport encoding and its response-size limit. This
//! crate owns request digests, validation, key authority and policy verdicts.

mod policy_bundle_crypto;
mod policy_bundle_decisions;
mod policy_bundle_delivery;
mod policy_bundle_families;
mod policy_bundle_json;
mod policy_bundle_keys;
mod policy_bundle_keys_ctx;
mod policy_bundle_op;
mod policy_bundle_op_delivery;
mod policy_bundle_op_keys;
mod policy_bundle_op_page;
#[cfg(test)]
mod policy_bundle_op_page_tests;
mod policy_bundle_op_synced;
#[cfg(test)]
mod policy_bundle_op_tests;
mod policy_bundle_op_validate;
#[cfg(test)]
mod policy_bundle_op_vectors_tests;
mod policy_bundle_py;
mod policy_bundle_time;
mod policy_bundle_v1;
mod policy_bundle_v1_rules;
mod policy_bundle_v2;
mod policy_bundle_v2_ack;

pub use policy_bundle_op::evaluate_policy_bundle_authority_request as evaluate;

/// Timestamp semantics shared with runtime callers.
pub mod time {
    pub use crate::policy_bundle_time::{
        from_isoformat, micros_to_utc_isoformat, strict_utc_micros, Parsed,
    };
}

/// Python string semantics shared with runtime callers.
pub mod python {
    pub use crate::policy_bundle_py::{is_hex64, is_py_space, non_empty, py_strip};
}

/// Verification-key loading shared with managed-policy persistence.
pub mod keys {
    pub use crate::policy_bundle_keys::{
        keys_to_value, load_keys, Key, KEYRING_CONTRACT_VERSION, KEY_PURPOSE,
    };
}

/// Canonical bytes used by managed-policy projections.
pub mod json {
    pub use crate::policy_bundle_json::v2_canonical_bytes;
}

/// Policy scope representability shared with package-policy resolution.
pub mod families {
    pub use crate::policy_bundle_families::saved_families;
}

/// Delivery and acknowledgement contracts shared with runtime projection tests.
pub mod delivery {
    pub use crate::policy_bundle_delivery::{ack_payload, validate_delivery, AckRequest};
}
