//! Stable refusal codes for the browser driver profile compiler.

/// Why a profile was refused. Each variant has a stable [`code`](Self::code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserDriverCompileError {
    SourceBytesInvalid,
    JsonInvalid,
    SchemaVersionUnsupported,
    IdInvalid,
    NameInvalid,
    PublisherInvalid,
    PublisherVerificationUnproven,
    ReferenceInvalid,
    MatchEmpty,
    MatchEntryInvalid,
    MatchEntryDuplicate,
    ReservedNameClaimed,
    ProfileModeInvalid,
    ToolsInvalid,
    ToolNameInvalid,
    ToolNameDuplicate,
    ToolShapeInvalid,
    VerbInvalid,
    PointerInvalid,
    CasesInvalid,
    VolatileFieldInvalid,
    IconInvalid,
    DriverIdDuplicate,
    DriverIdentityConflict,
}

impl BrowserDriverCompileError {
    /// Stable code for logs, fixtures and the contribution validator.
    pub fn code(self) -> &'static str {
        match self {
            Self::SourceBytesInvalid => "browser_driver_bytes_invalid",
            Self::JsonInvalid => "browser_driver_json_invalid",
            Self::SchemaVersionUnsupported => "browser_driver_schema_version_unsupported",
            Self::IdInvalid => "browser_driver_id_invalid",
            Self::NameInvalid => "browser_driver_name_invalid",
            Self::PublisherInvalid => "browser_driver_publisher_invalid",
            Self::PublisherVerificationUnproven => "browser_driver_publisher_verification_unproven",
            Self::ReferenceInvalid => "browser_driver_reference_invalid",
            Self::MatchEmpty => "browser_driver_match_empty",
            Self::MatchEntryInvalid => "browser_driver_match_entry_invalid",
            Self::MatchEntryDuplicate => "browser_driver_match_entry_duplicate",
            Self::ReservedNameClaimed => "browser_driver_reserved_name_claimed",
            Self::ProfileModeInvalid => "browser_driver_profile_mode_invalid",
            Self::ToolsInvalid => "browser_driver_tools_invalid",
            Self::ToolNameInvalid => "browser_driver_tool_name_invalid",
            Self::ToolNameDuplicate => "browser_driver_tool_name_duplicate",
            Self::ToolShapeInvalid => "browser_driver_tool_shape_invalid",
            Self::VerbInvalid => "browser_driver_verb_invalid",
            Self::PointerInvalid => "browser_driver_pointer_invalid",
            Self::CasesInvalid => "browser_driver_cases_invalid",
            Self::VolatileFieldInvalid => "browser_driver_volatile_field_invalid",
            Self::IconInvalid => "browser_driver_icon_invalid",
            Self::DriverIdDuplicate => "browser_driver_id_duplicate",
            Self::DriverIdentityConflict => "browser_driver_identity_conflict",
        }
    }
}
