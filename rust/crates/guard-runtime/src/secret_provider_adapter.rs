//! Reviewed external adapter core for HashiCorp Vault KV v2.
//!
//! This adapter is intentionally typed and bounded. It uses Guard's pinned
//! HTTPS transport, never invokes a provider CLI, and remains inert until the
//! caller supplies local enablement. The fixture host is synthetic.

use guard_provider_integrations::client::{
    ProviderLimits, ProviderMethod, ProviderRequest, ProviderTransport,
};
use guard_provider_integrations::parse::parse_strict_bounded;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::secret_store_platform::NativeSecret;

pub(crate) const PROVIDER_ID: &str = "provider.examplevault";
const HOST: &str = "vault.example.test";
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdapterError {
    Disabled,
    InvalidReference,
    Transport,
    Malformed,
    MissingValue,
}

impl AdapterError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Disabled => "secret_provider_disabled",
            Self::InvalidReference => "secret_provider_reference_invalid",
            Self::Transport => "secret_provider_unavailable",
            Self::Malformed => "secret_provider_response_malformed",
            Self::MissingValue => "secret_provider_value_missing",
        }
    }
}

pub(crate) struct VaultKvV2Adapter {
    enabled: bool,
    mount: String,
}

impl VaultKvV2Adapter {
    pub(crate) fn new(enabled: bool, mount: String) -> Result<Self, AdapterError> {
        if mount.is_empty()
            || mount.len() > 63
            || !mount
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(AdapterError::InvalidReference);
        }
        Ok(Self { enabled, mount })
    }

    pub(crate) fn resolve(
        &self,
        transport: &dyn ProviderTransport,
        token: Zeroizing<String>,
        scope: &str,
        name: &str,
        field: &str,
        version: Option<&str>,
    ) -> Result<(NativeSecret, Option<String>), AdapterError> {
        let response = self.exchange(transport, token, scope, name, version)?;
        let parsed = parse_strict_bounded(&response.body, MAX_RESPONSE_BYTES as usize)
            .ok_or(AdapterError::Malformed)?;
        let data = parsed
            .get("data")
            .and_then(Value::as_object)
            .ok_or(AdapterError::Malformed)?;
        let fields = data
            .get("data")
            .and_then(Value::as_object)
            .ok_or(AdapterError::Malformed)?;
        let value = fields
            .get(field)
            .and_then(Value::as_str)
            .ok_or(AdapterError::MissingValue)?;
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(AdapterError::Malformed);
        }
        let resolved_version = data
            .get("metadata")
            .and_then(|metadata| metadata.get("version"))
            .and_then(Value::as_u64)
            .map(|value| value.to_string());
        Ok((NativeSecret::new(value.to_owned()), resolved_version))
    }

    fn exchange(
        &self,
        transport: &dyn ProviderTransport,
        token: Zeroizing<String>,
        scope: &str,
        name: &str,
        version: Option<&str>,
    ) -> Result<guard_provider_integrations::client::ProviderResponse, AdapterError> {
        if !self.enabled {
            return Err(AdapterError::Disabled);
        }
        if !valid_segment(scope) || !valid_segment(name) {
            return Err(AdapterError::InvalidReference);
        }
        if version.is_some_and(|value| !valid_segment(value)) {
            return Err(AdapterError::InvalidReference);
        }
        let body = version.map(|value| format!(r#"{{"version":"{value}"}}"#));
        let request = ProviderRequest {
            method: ProviderMethod::Post,
            host: HOST.to_owned(),
            path: format!("/v1/{}/data/{scope}/{name}", self.mount),
            header: "x-vault-token".to_owned(),
            key: token,
            body,
        };
        transport
            .send(
                &request,
                ProviderLimits {
                    timeout_ms: 3000,
                    max_response_bytes: MAX_RESPONSE_BYTES,
                },
            )
            .map_err(|_| AdapterError::Transport)
            .and_then(|response| {
                if (200..300).contains(&response.status) {
                    Ok(response)
                } else {
                    Err(AdapterError::Transport)
                }
            })
    }
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_provider_integrations::client::{ProviderResponse, ProviderTransport};

    struct FixtureTransport;

    impl ProviderTransport for FixtureTransport {
        fn send(
            &self,
            request: &ProviderRequest,
            _limits: ProviderLimits,
        ) -> Result<ProviderResponse, guard_provider_integrations::ProviderClientError> {
            assert_eq!(request.host, HOST);
            assert_eq!(request.path, "/v1/fixture/data/team/token");
            assert_eq!(request.header, "x-vault-token");
            assert_eq!(request.body.as_deref(), Some(r#"{"version":"2"}"#));
            Ok(ProviderResponse {
                status: 200,
                body: br#"{"data":{"data":{"value":"fixture-value-7"},"metadata":{"version":2}}}"#
                    .to_vec(),
            })
        }
    }

    #[test]
    fn disabled_provider_never_calls_transport() {
        let adapter = VaultKvV2Adapter::new(false, "fixture".to_owned()).unwrap();
        let result = adapter.resolve(
            &FixtureTransport,
            Zeroizing::new("fixture-token".to_owned()),
            "team",
            "token",
            "value",
            None,
        );
        assert_eq!(result.unwrap_err(), AdapterError::Disabled);
    }

    #[test]
    fn bounded_fixture_resolves_value_only_to_native_type() {
        let adapter = VaultKvV2Adapter::new(true, "fixture".to_owned()).unwrap();
        let (secret, version) = adapter
            .resolve(
                &FixtureTransport,
                Zeroizing::new("fixture-token".to_owned()),
                "team",
                "token",
                "value",
                Some("2"),
            )
            .unwrap();
        assert_eq!(secret.expose(), "fixture-value-7");
        assert_eq!(version.as_deref(), Some("2"));
        assert!(!format!("{secret:?}").contains("fixture-value-7"));
    }
}
