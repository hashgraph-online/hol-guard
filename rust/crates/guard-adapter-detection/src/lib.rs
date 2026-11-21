#![forbid(unsafe_code)]

//! Harness detection leaves for `runner_authority`: each detector owns its
//! config parsing and artifact discovery and talks to the runtime only through
//! [`DetectionHost`]. The port is a compile-time interface over the shared
//! inventory, not a policy override.

pub mod artifacts;
pub mod gemini;
pub mod host;
pub mod payload;

pub use artifacts::{Fields, Scope};
pub use host::{DetectionHost, DetectionRequest, SkillNaming};
pub use payload::{
    carried, json_document, json_payload, mcp_fields, string_args, ERR_NAME, ERR_TEXT, ERR_VALUE,
};
