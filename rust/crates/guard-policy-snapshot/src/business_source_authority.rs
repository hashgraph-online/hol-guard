//! Authenticated whole-source bytes for the local installation owner.
//!
//! A valid MAC establishes signing-key origin and exact source identity only.
//! The caller must separately verify approval, retained mutation/recovery floors
//! and currentness. This codec cannot install a policy or authorize a dispatch.

use crate::business_policy_document::{
    compile_business_document, CompiledBusinessDocument, MAX_BUSINESS_POLICY_DOCUMENT_BYTES,
};
use crate::crypto::{constant_time_eq, hmac_sha256_raw};
use crate::{canonical_json_bytes, digest_bytes, verifier_key_id};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const BUSINESS_SOURCE_AUTHORITY_SCHEMA: &str = "guard.business-source-authority.v1";
pub const MAX_BUSINESS_SOURCE_AUTHORITY_BYTES: usize = MAX_BUSINESS_POLICY_DOCUMENT_BYTES + 8192;
const MAC_DOMAIN: &[u8] = b"hol-guard.business-source-authority.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusinessSourceError {
    Bounds,
    InvalidRecord,
    InvalidSource,
    Authentication,
    Rollback,
    RevisionConflict,
}

/// Retained identity must be loaded from independently authenticated storage.
/// Serialization alone does not make an anchor trusted or prove its existence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BusinessSourceFloor {
    mutation_revision: u64,
    record_digest: String,
    source_digest: String,
    source_id: String,
    source_revision: u64,
    business_policy_digest: String,
}

impl BusinessSourceFloor {
    pub fn mutation_revision(&self) -> u64 {
        self.mutation_revision
    }

    pub fn business_policy_digest(&self) -> &str {
        &self.business_policy_digest
    }

    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }

    pub(crate) fn validate(&self) -> Result<(), BusinessSourceError> {
        let valid_digest = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if self.mutation_revision == 0
            || self.source_id.is_empty()
            || self.source_id.len() > 4096
            || !valid_digest(&self.record_digest)
            || !valid_digest(&self.source_digest)
            || !valid_digest(&self.business_policy_digest)
        {
            return Err(BusinessSourceError::InvalidRecord);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BusinessSourceRecord {
    schema: String,
    mutation_revision: u64,
    import_mode: String,
    source_document: Value,
    source_digest: String,
    authority_key_id: String,
    mac: String,
}

/// Private construction prevents caller JSON becoming a verified source value.
/// This value still carries no approval, installation or currentness evidence.
pub struct VerifiedBusinessSource {
    compiled: CompiledBusinessDocument,
    mutation_revision: u64,
    record_digest: String,
    source_id: String,
    source_revision: u64,
    business_policy_digest: String,
    authority_key_id: String,
}

impl VerifiedBusinessSource {
    pub fn compiled(&self) -> &CompiledBusinessDocument {
        &self.compiled
    }

    pub fn mutation_revision(&self) -> u64 {
        self.mutation_revision
    }

    pub fn record_digest(&self) -> &str {
        &self.record_digest
    }

    pub fn authority_key_id(&self) -> &str {
        &self.authority_key_id
    }

    pub fn floor(&self) -> BusinessSourceFloor {
        BusinessSourceFloor {
            mutation_revision: self.mutation_revision,
            record_digest: self.record_digest.clone(),
            source_digest: self.compiled.source_digest().to_owned(),
            source_id: self.source_id.clone(),
            source_revision: self.source_revision,
            business_policy_digest: self.business_policy_digest.clone(),
        }
    }

    /// Equal mutation revisions allow only exact record replay. New mutations
    /// cannot rewrite the content of a retained document revision or roll it back.
    pub fn check_retained_floor(
        &self,
        floor: &BusinessSourceFloor,
    ) -> Result<(), BusinessSourceError> {
        floor.validate()?;
        if self.mutation_revision < floor.mutation_revision
            || (self.mutation_revision == floor.mutation_revision
                && self.record_digest != floor.record_digest)
        {
            return Err(BusinessSourceError::Rollback);
        }
        if self.source_id == floor.source_id
            && (self.source_revision < floor.source_revision
                || (self.source_revision == floor.source_revision
                    && (self.compiled.source_digest() != floor.source_digest
                        || self.business_policy_digest != floor.business_policy_digest)))
        {
            return Err(BusinessSourceError::RevisionConflict);
        }
        Ok(())
    }
}

fn record_bytes(record: &BusinessSourceRecord) -> Result<Vec<u8>, BusinessSourceError> {
    let value = serde_json::to_value(record).map_err(|_| BusinessSourceError::InvalidRecord)?;
    canonical_json_bytes(&value).map_err(|_| BusinessSourceError::InvalidRecord)
}

fn signing_mac(
    record: &BusinessSourceRecord,
    verifier_key: &[u8; 32],
) -> Result<String, BusinessSourceError> {
    let mut value = serde_json::to_value(record).map_err(|_| BusinessSourceError::InvalidRecord)?;
    value
        .as_object_mut()
        .ok_or(BusinessSourceError::InvalidRecord)?
        .remove("mac");
    let mut message = MAC_DOMAIN.to_vec();
    message.extend_from_slice(
        &canonical_json_bytes(&value).map_err(|_| BusinessSourceError::InvalidRecord)?,
    );
    Ok(hex::encode(hmac_sha256_raw(verifier_key, &message)))
}

/// The trusted installation owner supplies its key after exact-document approval.
/// Unsupported document semantics refuse through the existing Rust compiler.
/// Only whole-document replacement is representable; merge is not implicit.
pub fn sign_business_source(
    source_document: &Value,
    mutation_revision: u64,
    verifier_key: &[u8; 32],
) -> Result<Vec<u8>, BusinessSourceError> {
    if mutation_revision == 0 {
        return Err(BusinessSourceError::InvalidRecord);
    }
    let compiled = compile_business_document(source_document)
        .map_err(|_| BusinessSourceError::InvalidSource)?;
    if source_document["metadata"]["id"].as_str().is_none()
        || source_document["metadata"]["revision"].as_u64().is_none()
    {
        return Err(BusinessSourceError::InvalidSource);
    }
    let mut record = BusinessSourceRecord {
        schema: BUSINESS_SOURCE_AUTHORITY_SCHEMA.to_owned(),
        mutation_revision,
        import_mode: "replace".to_owned(),
        source_document: source_document.clone(),
        source_digest: compiled.source_digest().to_owned(),
        authority_key_id: verifier_key_id(verifier_key),
        mac: String::new(),
    };
    record.mac = signing_mac(&record, verifier_key)?;
    let bytes = record_bytes(&record)?;
    if bytes.len() > MAX_BUSINESS_SOURCE_AUTHORITY_BYTES {
        return Err(BusinessSourceError::Bounds);
    }
    Ok(bytes)
}

pub fn verify_business_source(
    bytes: &[u8],
    verifier_key: &[u8; 32],
) -> Result<VerifiedBusinessSource, BusinessSourceError> {
    if bytes.len() > MAX_BUSINESS_SOURCE_AUTHORITY_BYTES {
        return Err(BusinessSourceError::Bounds);
    }
    let record: BusinessSourceRecord =
        serde_json::from_slice(bytes).map_err(|_| BusinessSourceError::InvalidRecord)?;
    if record.schema != BUSINESS_SOURCE_AUTHORITY_SCHEMA
        || record.mutation_revision == 0
        || record.import_mode != "replace"
        || record_bytes(&record)? != bytes
    {
        return Err(BusinessSourceError::InvalidRecord);
    }
    if !constant_time_eq(
        record.authority_key_id.as_bytes(),
        verifier_key_id(verifier_key).as_bytes(),
    ) || !constant_time_eq(
        record.mac.as_bytes(),
        signing_mac(&record, verifier_key)?.as_bytes(),
    ) {
        return Err(BusinessSourceError::Authentication);
    }
    let compiled = compile_business_document(&record.source_document)
        .map_err(|_| BusinessSourceError::InvalidSource)?;
    if compiled.source_digest() != record.source_digest {
        return Err(BusinessSourceError::InvalidRecord);
    }
    let source_id = record.source_document["metadata"]["id"]
        .as_str()
        .ok_or(BusinessSourceError::InvalidSource)?
        .to_owned();
    let source_revision = record.source_document["metadata"]["revision"]
        .as_u64()
        .ok_or(BusinessSourceError::InvalidSource)?;
    let binding_value =
        serde_json::to_value(compiled.binding()).map_err(|_| BusinessSourceError::InvalidSource)?;
    let business_policy_digest = digest_bytes(
        &canonical_json_bytes(&binding_value).map_err(|_| BusinessSourceError::InvalidSource)?,
    );
    Ok(VerifiedBusinessSource {
        compiled,
        mutation_revision: record.mutation_revision,
        record_digest: digest_bytes(bytes),
        source_id,
        source_revision,
        business_policy_digest,
        authority_key_id: record.authority_key_id,
    })
}

#[cfg(test)]
#[path = "business_source_authority_tests.rs"]
mod tests;
