//! Caller-declared lookup context shared by hook and command entry points.
use serde::{Deserialize, Serialize};

pub const MAX_EXECUTION_ENVIRONMENT_PATH_BYTES: usize = 32 * 1024;
pub const MAX_EXECUTION_ENVIRONMENT_NAMES: usize = 512;
pub const MAX_EXECUTION_ENVIRONMENT_NAME_BYTES: usize = 256;
pub const EXECUTION_ENVIRONMENT_DIGEST_HEX_BYTES: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardExecutionEnvironmentV1 {
    pub path: String,
    pub environment_names: Vec<String>,
    /// Opaque sender commitment for request identity, not verified integrity.
    /// Withheld values cannot be recomputed by the receiver; this is not a MAC.
    pub environment_digest: String,
    #[serde(default)]
    pub home: Option<String>,
    #[serde(default)]
    pub git_pager_disabled: bool,
    #[serde(default)]
    pub pager_disabled: bool,
    #[serde(default)]
    pub xdg_config_home: Option<String>,
    #[serde(default)]
    pub git_config_no_system: bool,
}

impl GuardExecutionEnvironmentV1 {
    /// Validate the bounds needed for Git lookup admission, not sender integrity.
    /// Other hooks remain subject to the independent whole-envelope limits.
    pub fn has_valid_shape(&self) -> bool {
        let path_valid =
            |path: &str| path.len() <= MAX_EXECUTION_ENVIRONMENT_PATH_BYTES && !path.contains('\0');
        path_valid(&self.path)
            && self.home.as_deref().is_none_or(path_valid)
            && self.xdg_config_home.as_deref().is_none_or(path_valid)
            && self.environment_names.len() <= MAX_EXECUTION_ENVIRONMENT_NAMES
            && self.environment_names.iter().all(|name| {
                name.len() <= MAX_EXECUTION_ENVIRONMENT_NAME_BYTES
                    && !name.chars().any(char::is_control)
            })
            && self.environment_digest.len() == EXECUTION_ENVIRONMENT_DIGEST_HEX_BYTES
            && self
                .environment_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    pub fn unavailable() -> Self {
        Self {
            path: String::new(),
            environment_names: Vec::new(),
            environment_digest: String::new(),
            home: None,
            git_pager_disabled: false,
            pager_disabled: false,
            xdg_config_home: None,
            git_config_no_system: false,
        }
    }
}
