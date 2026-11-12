use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigError(pub &'static str);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceProfile {
    LowMemory,
    #[default]
    Balanced,
    Custom,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageMode {
    #[default]
    Memory,
    Sqlite,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Features {
    pub review_briefs: bool,
    pub agent_context: bool,
    pub shared_agents: bool,
    pub execution_context: bool,
}

impl Default for Features {
    fn default() -> Self {
        Self {
            review_briefs: true,
            agent_context: false,
            shared_agents: false,
            execution_context: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Sources {
    pub native_policy_facts: bool,
    pub sanitized_receipt_facts: bool,
    pub workspace_documents: bool,
    pub source_set_id: String,
}

impl Default for Sources {
    fn default() -> Self {
        Self {
            native_policy_facts: true,
            sanitized_receipt_facts: true,
            workspace_documents: false,
            source_set_id: String::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Storage {
    pub mode: StorageMode,
    pub retention_hours: u32,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            mode: StorageMode::Memory,
            retention_hours: 24,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub context_tokens: u32,
    pub reserve_tokens: u32,
    pub max_active_workspaces: u32,
    pub idle_shutdown_seconds: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            context_tokens: 2048,
            reserve_tokens: 256,
            max_active_workspaces: 2,
            idle_shutdown_seconds: 600,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContextAssistanceConfig {
    pub schema_version: u32,
    pub enabled: bool,
    pub runtime_id: String,
    pub resource_profile: ResourceProfile,
    pub features: Features,
    pub sources: Sources,
    pub storage: Storage,
    pub limits: Limits,
}

impl Default for ContextAssistanceConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            enabled: false,
            runtime_id: String::new(),
            resource_profile: ResourceProfile::Balanced,
            features: Features::default(),
            sources: Sources::default(),
            storage: Storage::default(),
            limits: Limits::default(),
        }
    }
}

fn valid_id(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-:".contains(&byte))
}

impl ContextAssistanceConfig {
    /// Portable preferences contain neither activation intent nor machine-local
    /// runtime/source references. Importing them requires fresh local selection.
    pub fn for_export(&self) -> Self {
        let mut portable = self.clone();
        portable.enabled = false;
        portable.runtime_id.clear();
        portable.sources.workspace_documents = false;
        portable.sources.source_set_id.clear();
        portable
    }

    /// Strict settings validation. This records intent, not runtime readiness.
    pub fn parse(value: Value) -> Result<Self, ConfigError> {
        let config: Self = serde_json::from_value(value)
            .map_err(|_| ConfigError("context_assistance_schema_invalid"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let error = if self.schema_version != 1 {
            Some("context_assistance_schema_unsupported")
        } else if !valid_id(&self.runtime_id) || (self.enabled && self.runtime_id.is_empty()) {
            Some("context_assistance_runtime_id_invalid")
        } else if self.features.shared_agents && !self.features.agent_context {
            Some("context_assistance_sharing_requires_agent_context")
        } else if !valid_id(&self.sources.source_set_id)
            || (self.sources.workspace_documents && self.sources.source_set_id.is_empty())
        {
            Some("context_assistance_source_set_invalid")
        } else if !(64..=16_384).contains(&self.limits.context_tokens)
            || self.limits.reserve_tokens >= self.limits.context_tokens
        {
            Some("context_assistance_token_budget_invalid")
        } else if !(1..=8).contains(&self.limits.max_active_workspaces) {
            Some("context_assistance_workspace_limit_invalid")
        } else if !(30..=3_600).contains(&self.limits.idle_shutdown_seconds) {
            Some("context_assistance_idle_timeout_invalid")
        } else if !(1..=720).contains(&self.storage.retention_hours) {
            Some("context_assistance_retention_invalid")
        } else {
            None
        };
        error.map_or(Ok(()), |code| Err(ConfigError(code)))
    }

    /// Malformed persisted configuration must never acquire an enabled state.
    /// The control plane retains the diagnostic independently from these defaults.
    pub fn load(value: Option<&Value>) -> (Self, Option<ConfigError>) {
        match value {
            None => (Self::default(), None),
            Some(value) => match Self::parse(value.clone()) {
                Ok(config) => (config, None),
                Err(error) => (Self::default(), Some(error)),
            },
        }
    }
}
