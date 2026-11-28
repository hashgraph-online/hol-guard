//! Canonical guard-secret references.
//!
//! References identify a provider record without carrying a value. The
//! parser is deliberately strict because the canonical form becomes part of
//! approval and cache bindings.

use percent_encoding::percent_decode_str;
use sha2::{Digest, Sha256};

const PREFIX: &str = "guard-secret://";
const MAX_SEGMENT_BYTES: usize = 63;
const MAX_REFERENCE_BYTES: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SecretReference {
    pub(crate) provider: String,
    pub(crate) scope: String,
    pub(crate) name: String,
    pub(crate) field: Option<String>,
    pub(crate) version: Option<String>,
}

impl SecretReference {
    pub(crate) fn parse(input: &str) -> Result<Self, String> {
        if input.len() > MAX_REFERENCE_BYTES || !input.starts_with(PREFIX) {
            return Err("secret_reference_invalid".to_owned());
        }
        let body = &input[PREFIX.len()..];
        let (path, version) = match body.split_once('?') {
            Some((path, query)) if !query.is_empty() && !query.contains('?') => {
                let Some(value) = query.strip_prefix("version=") else {
                    return Err("secret_reference_invalid".to_owned());
                };
                (path, Some(parse_segment(value, true)?))
            }
            Some(_) => return Err("secret_reference_invalid".to_owned()),
            None => (body, None),
        };
        let (path, field) = match path.split_once('#') {
            Some((path, value)) if !value.is_empty() && !value.contains('#') => {
                (path, Some(parse_segment(value, false)?))
            }
            Some(_) => return Err("secret_reference_invalid".to_owned()),
            None => (path, None),
        };
        let mut segments = path.split('/');
        let provider = parse_segment(
            segments
                .next()
                .ok_or_else(|| "secret_reference_invalid".to_owned())?,
            false,
        )?;
        let scope = parse_segment(
            segments
                .next()
                .ok_or_else(|| "secret_reference_invalid".to_owned())?,
            false,
        )?;
        let name = parse_segment(
            segments
                .next()
                .ok_or_else(|| "secret_reference_invalid".to_owned())?,
            false,
        )?;
        if segments.next().is_some() || !valid_provider(&provider) {
            return Err("secret_reference_invalid".to_owned());
        }
        let reference = Self {
            provider,
            scope,
            name,
            field,
            version,
        };
        if reference.to_string().len() > MAX_REFERENCE_BYTES {
            return Err("secret_reference_invalid".to_owned());
        }
        Ok(reference)
    }

    pub(crate) fn canonical_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.to_string().as_bytes());
        hex::encode(hasher.finalize())
    }
}

impl std::fmt::Display for SecretReference {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{PREFIX}{}/{}/{}",
            self.provider, self.scope, self.name
        )?;
        if let Some(field) = &self.field {
            write!(formatter, "#{field}")?;
        }
        if let Some(version) = &self.version {
            write!(formatter, "?version={version}")?;
        }
        Ok(())
    }
}

fn valid_provider(provider: &str) -> bool {
    provider == "native" || provider.starts_with("provider.")
}

fn parse_segment(value: &str, allow_latest: bool) -> Result<String, String> {
    let decoded = percent_decode_str(value)
        .decode_utf8()
        .map_err(|_| "secret_reference_invalid".to_owned())?;
    let decoded = decoded.as_ref();
    if decoded.is_empty()
        || decoded.len() > MAX_SEGMENT_BYTES
        || decoded == "."
        || decoded == ".."
        || decoded.chars().any(|character| {
            character.is_control()
                || character == '/'
                || character == '\\'
                || character.is_whitespace()
        })
        || (!allow_latest && decoded == "latest")
    {
        return Err("secret_reference_invalid".to_owned());
    }
    if !decoded
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("secret_reference_invalid".to_owned());
    }
    Ok(decoded.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes_a_native_reference() {
        let reference = SecretReference::parse("guard-secret://native/project-api/token").unwrap();
        assert_eq!(
            reference.to_string(),
            "guard-secret://native/project-api/token"
        );
        assert_eq!(reference.provider, "native");
        assert_eq!(reference.scope, "project-api");
        assert_eq!(reference.name, "token");
    }

    #[test]
    fn supports_field_and_version_selectors() {
        let reference = SecretReference::parse(
            "guard-secret://provider.examplevault/team%2Done/item#value?version=v2",
        )
        .unwrap();
        assert_eq!(
            reference.to_string(),
            "guard-secret://provider.examplevault/team-one/item#value?version=v2"
        );
    }

    #[test]
    fn accepts_latest_only_as_a_version_selector() {
        assert!(SecretReference::parse("guard-secret://native/scope/name?version=latest").is_ok());
        assert!(SecretReference::parse("guard-secret://native/scope/name#latest").is_err());
    }

    #[test]
    fn rejects_ambiguous_or_value_bearing_references() {
        for value in [
            "",
            "native/project/name",
            "guard-secret://native//name",
            "guard-secret://native/../name",
            "guard-secret://native/scope/name?token=secret",
            "guard-secret://other/scope/name",
            "guard-secret://provider.examplevault/scope/name%2Fchild",
            "guard-secret://native/scope/name#",
        ] {
            assert!(
                SecretReference::parse(value).is_err(),
                "reference unexpectedly accepted: {value}"
            );
        }
    }

    #[test]
    fn digest_changes_when_binding_fields_change() {
        let first = SecretReference::parse("guard-secret://native/scope/name").unwrap();
        let second = SecretReference::parse("guard-secret://native/scope/name?version=v2").unwrap();
        assert_ne!(first.canonical_digest(), second.canonical_digest());
    }
}
