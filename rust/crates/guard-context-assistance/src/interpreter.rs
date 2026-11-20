use serde::{Deserialize, Serialize};

/// Host facts recorded with a runtime status. The built-in engine runs inside
/// Guard and reports that it has no separate interpreter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterpreterFacts {
    pub schema: String,
    pub implementation: String,
    pub version: [u16; 3],
    pub release_level: String,
    pub free_threaded: bool,
    pub debug_build: bool,
    pub abi: String,
    pub platform: String,
}
