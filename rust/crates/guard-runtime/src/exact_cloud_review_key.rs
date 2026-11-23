//! The key exact Cloud Review signs and checks consent with: the copy the
//! caller sends, or the one in the Guard home's own vault.

use std::path::{Path, PathBuf};

use base64ct::{Base64UrlUnpadded, Encoding};

use super::Refusal;
use crate::command_envelope_op::resident_key;

/// Who asks: the spawned helper reads the vault the request names; the
/// resident reads only its own home's vault.
#[derive(Clone, Copy)]
pub(super) enum Caller<'a> {
    Helper,
    Resident(Option<&'a Path>),
}

/// The local signing key and its id.
pub(super) struct SigningKey {
    key: Option<String>,
    key_id: Option<String>,
}

impl SigningKey {
    pub(super) fn material(&self) -> Result<(Vec<u8>, &str), Refusal> {
        let key = self
            .key
            .as_deref()
            .and_then(|key| Base64UrlUnpadded::decode_vec(key).ok());
        match (key, self.key_id.as_deref()) {
            (Some(key), Some(key_id)) => Ok((key, key_id)),
            _ => Err(Refusal::code("cloud_review_signing_key_unavailable")),
        }
    }
}

/// The key a request signs or checks with. A request that names
/// `vault_home` and also carries a key or key id is malformed: a caller must
/// not mix its own key with the home's. A vault the caller may not read, or
/// one that holds no key, is no key, which `material` refuses.
pub(super) fn signing_key(
    key: Option<String>,
    key_id: Option<String>,
    vault_home: Option<String>,
    caller: Caller<'_>,
) -> Result<SigningKey, Refusal> {
    let Some(vault_home) = vault_home.map(PathBuf::from) else {
        return Ok(SigningKey { key, key_id });
    };
    if key.is_some() || key_id.is_some() || !vault_home.is_absolute() {
        return Err(Refusal::Fault("exact_cloud_review_request_invalid"));
    }
    let readable = match caller {
        Caller::Helper => true,
        Caller::Resident(home) => home.is_some_and(|home| same_home(home, &vault_home)),
    };
    let (key, key_id) = if readable {
        resident_key(Some(&vault_home))
    } else {
        (None, None)
    };
    Ok(SigningKey { key, key_id })
}

fn same_home(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

#[cfg(test)]
#[path = "exact_cloud_review_key_tests.rs"]
mod tests;
