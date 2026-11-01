//! Preferences constrain discovery/preparation; they never authorize activation.
use crate::{types::identifier, ReleaseError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateMode {
    #[default]
    Manual,
    Notify,
    Prepare,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpdatePreferences {
    pub mode: UpdateMode,
    pub allow_preview: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned_build: Option<String>,
    pub retain_last_good: bool,
}
impl Default for UpdatePreferences {
    fn default() -> Self {
        Self {
            mode: UpdateMode::Manual,
            allow_preview: false,
            pinned_build: None,
            retain_last_good: true,
        }
    }
}
impl UpdatePreferences {
    pub fn validate(&self) -> Result<(), ReleaseError> {
        if self
            .pinned_build
            .as_deref()
            .is_some_and(|id| !identifier(id))
        {
            return Err(ReleaseError::InvalidUpdatePreferences);
        }
        Ok(())
    }
    pub fn parse(value: Value) -> Result<Self, ReleaseError> {
        let parsed: Self =
            serde_json::from_value(value).map_err(|_| ReleaseError::InvalidUpdatePreferences)?;
        parsed.validate()?;
        Ok(parsed)
    }
    /// Machine policy is a ceiling on optional work and preview consent.
    /// It can require retaining recovery bytes or a particular exact build.
    /// A missing/null pin never clears the user's pin.
    pub fn restrict(&self, managed: &Value) -> Result<Self, ReleaseError> {
        let invalid = || ReleaseError::InvalidUpdatePreferences;
        let map = managed.as_object().ok_or_else(invalid)?;
        let mut result = self.clone();
        for (key, value) in map {
            match key.as_str() {
                "mode" => {
                    let mode: UpdateMode =
                        serde_json::from_value(value.clone()).map_err(|_| invalid())?;
                    let rank = |m| match m {
                        UpdateMode::Manual => 0,
                        UpdateMode::Notify => 1,
                        UpdateMode::Prepare => 2,
                    };
                    if rank(mode) < rank(result.mode) {
                        result.mode = mode;
                    }
                }
                "allow_preview" => result.allow_preview &= value.as_bool().ok_or_else(invalid)?,
                "retain_last_good" => {
                    result.retain_last_good |= value.as_bool().ok_or_else(invalid)?
                }
                "pinned_build" if value.is_null() => {}
                "pinned_build" => {
                    let id = value
                        .as_str()
                        .filter(|s| identifier(s))
                        .ok_or_else(invalid)?;
                    result.pinned_build = Some(id.into());
                }
                _ => return Err(invalid()),
            }
        }
        result.validate()?;
        Ok(result)
    }
}
