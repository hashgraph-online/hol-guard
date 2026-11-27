//! Stable refusal codes for the provider integration compiler.

/// Why a manifest was refused. Each variant has a stable [`code`](Self::code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIntegrationCompileError {
    SourceBytesInvalid,
    JsonInvalid,
    SchemaVersionUnsupported,
    IdInvalid,
    NameInvalid,
    SummaryInvalid,
    PublisherInvalid,
    PublisherVerificationUnproven,
    SurfacesInvalid,
    AuthKindUnsupported,
    AuthKindReserved,
    AuthHeaderInvalid,
    KeyFormatInvalid,
    HostsInvalid,
    HostInvalid,
    CapabilitiesInvalid,
    CapabilityUnknown,
    CapabilityDuplicate,
    RequestMethodInvalid,
    RequestHostInvalid,
    RequestPathInvalid,
    RequestBodyInvalid,
    FactUnknown,
    SharesMismatch,
    ResponsePointerInvalid,
    VerdictMapInvalid,
    ReasonCodesInvalid,
    ReasonLabelInvalid,
    TtlInvalid,
    VerifyInvalid,
    LimitsInvalid,
    PolicyUrlInvalid,
    IconInvalid,
    ProviderIdDuplicate,
    /// A manifest under `contributions/` claims the id prefix reserved for the fixture origin.
    FixtureIdContributed,
}

impl ProviderIntegrationCompileError {
    /// Stable code for logs, fixtures and the contribution validator.
    pub fn code(self) -> &'static str {
        match self {
            Self::SourceBytesInvalid => "provider_integration_bytes_invalid",
            Self::JsonInvalid => "provider_integration_json_invalid",
            Self::SchemaVersionUnsupported => "provider_integration_schema_version_unsupported",
            Self::IdInvalid => "provider_integration_id_invalid",
            Self::NameInvalid => "provider_integration_name_invalid",
            Self::SummaryInvalid => "provider_integration_summary_invalid",
            Self::PublisherInvalid => "provider_integration_publisher_invalid",
            Self::PublisherVerificationUnproven => {
                "provider_integration_publisher_verification_unproven"
            }
            Self::SurfacesInvalid => "provider_integration_surfaces_invalid",
            Self::AuthKindUnsupported => "provider_integration_auth_kind_unsupported",
            Self::AuthKindReserved => "provider_integration_auth_kind_reserved",
            Self::AuthHeaderInvalid => "provider_integration_auth_header_invalid",
            Self::KeyFormatInvalid => "provider_integration_key_format_invalid",
            Self::HostsInvalid => "provider_integration_hosts_invalid",
            Self::HostInvalid => "provider_integration_host_invalid",
            Self::CapabilitiesInvalid => "provider_integration_capabilities_invalid",
            Self::CapabilityUnknown => "provider_integration_capability_unknown",
            Self::CapabilityDuplicate => "provider_integration_capability_duplicate",
            Self::RequestMethodInvalid => "provider_integration_request_method_invalid",
            Self::RequestHostInvalid => "provider_integration_request_host_invalid",
            Self::RequestPathInvalid => "provider_integration_request_path_invalid",
            Self::RequestBodyInvalid => "provider_integration_request_body_invalid",
            Self::FactUnknown => "provider_integration_fact_unknown",
            Self::SharesMismatch => "provider_integration_shares_mismatch",
            Self::ResponsePointerInvalid => "provider_integration_response_pointer_invalid",
            Self::VerdictMapInvalid => "provider_integration_verdict_map_invalid",
            Self::ReasonCodesInvalid => "provider_integration_reason_codes_invalid",
            Self::ReasonLabelInvalid => "provider_integration_reason_label_invalid",
            Self::TtlInvalid => "provider_integration_ttl_invalid",
            Self::VerifyInvalid => "provider_integration_verify_invalid",
            Self::LimitsInvalid => "provider_integration_limits_invalid",
            Self::PolicyUrlInvalid => "provider_integration_policy_url_invalid",
            Self::IconInvalid => "provider_integration_icon_invalid",
            Self::ProviderIdDuplicate => "provider_integration_id_duplicate",
            Self::FixtureIdContributed => "provider_integration_fixture_id_contributed",
        }
    }
}

impl std::fmt::Display for ProviderIntegrationCompileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProviderIntegrationCompileError {}
