//! Bounded source-mutation marker. Its MAC authenticates a requested phase;
//! approval and independent durable retention remain installation-owner duties.

use crate::business_source_authority::{
    BusinessSourceError, BusinessSourceFloor, VerifiedBusinessSource,
};
use crate::crypto::{constant_time_eq, hmac_sha256_raw};
use crate::{canonical_json_bytes, digest_bytes, verifier_key_id};
use serde::{Deserialize, Serialize};

pub const BUSINESS_SOURCE_ANCHOR_SCHEMA: &str = "guard.business-source-anchor.v1";
pub const MAX_BUSINESS_SOURCE_ANCHOR_BYTES: usize = 4096;
const MAC_DOMAIN: &[u8] = b"hol-guard.business-source-anchor.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BusinessSourcePhase {
    Closed,
    Committed,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorRecord {
    schema: String,
    phase: BusinessSourcePhase,
    floor: BusinessSourceFloor,
    authority_key_id: String,
    mac: String,
}

pub struct VerifiedBusinessSourceAnchor {
    phase: BusinessSourcePhase,
    floor: BusinessSourceFloor,
    authority_key_id: String,
    anchor_digest: String,
}

impl VerifiedBusinessSourceAnchor {
    pub fn phase(&self) -> BusinessSourcePhase {
        self.phase
    }

    pub fn floor(&self) -> &BusinessSourceFloor {
        &self.floor
    }

    pub fn anchor_digest(&self) -> &str {
        &self.anchor_digest
    }

    pub fn check_committed_source(
        &self,
        source: &VerifiedBusinessSource,
    ) -> Result<(), BusinessSourceError> {
        if !constant_time_eq(
            self.authority_key_id.as_bytes(),
            source.authority_key_id().as_bytes(),
        ) {
            return Err(BusinessSourceError::Authentication);
        }
        if self.phase != BusinessSourcePhase::Committed || self.floor != source.floor() {
            return Err(BusinessSourceError::RevisionConflict);
        }
        Ok(())
    }
}

fn bytes(record: &AnchorRecord) -> Result<Vec<u8>, BusinessSourceError> {
    let value = serde_json::to_value(record).map_err(|_| BusinessSourceError::InvalidRecord)?;
    canonical_json_bytes(&value).map_err(|_| BusinessSourceError::InvalidRecord)
}

fn mac(record: &AnchorRecord, key: &[u8; 32]) -> Result<String, BusinessSourceError> {
    let mut value = serde_json::to_value(record).map_err(|_| BusinessSourceError::InvalidRecord)?;
    value
        .as_object_mut()
        .ok_or(BusinessSourceError::InvalidRecord)?
        .remove("mac");
    let mut message = MAC_DOMAIN.to_vec();
    message.extend_from_slice(
        &canonical_json_bytes(&value).map_err(|_| BusinessSourceError::InvalidRecord)?,
    );
    Ok(hex::encode(hmac_sha256_raw(key, &message)))
}

pub fn sign_business_source_anchor(
    source: &VerifiedBusinessSource,
    phase: BusinessSourcePhase,
    key: &[u8; 32],
) -> Result<Vec<u8>, BusinessSourceError> {
    if !constant_time_eq(
        source.authority_key_id().as_bytes(),
        verifier_key_id(key).as_bytes(),
    ) {
        return Err(BusinessSourceError::Authentication);
    }
    let mut record = AnchorRecord {
        schema: BUSINESS_SOURCE_ANCHOR_SCHEMA.to_owned(),
        phase,
        floor: source.floor(),
        authority_key_id: source.authority_key_id().to_owned(),
        mac: String::new(),
    };
    record.mac = mac(&record, key)?;
    let result = bytes(&record)?;
    if result.len() > MAX_BUSINESS_SOURCE_ANCHOR_BYTES {
        return Err(BusinessSourceError::Bounds);
    }
    Ok(result)
}

pub fn verify_business_source_anchor(
    wire: &[u8],
    key: &[u8; 32],
) -> Result<VerifiedBusinessSourceAnchor, BusinessSourceError> {
    if wire.len() > MAX_BUSINESS_SOURCE_ANCHOR_BYTES {
        return Err(BusinessSourceError::Bounds);
    }
    let record: AnchorRecord =
        serde_json::from_slice(wire).map_err(|_| BusinessSourceError::InvalidRecord)?;
    if record.schema != BUSINESS_SOURCE_ANCHOR_SCHEMA || bytes(&record)? != wire {
        return Err(BusinessSourceError::InvalidRecord);
    }
    if !constant_time_eq(
        record.authority_key_id.as_bytes(),
        verifier_key_id(key).as_bytes(),
    ) || !constant_time_eq(record.mac.as_bytes(), mac(&record, key)?.as_bytes())
    {
        return Err(BusinessSourceError::Authentication);
    }
    record.floor.validate()?;
    Ok(VerifiedBusinessSourceAnchor {
        phase: record.phase,
        floor: record.floor,
        authority_key_id: record.authority_key_id,
        anchor_digest: digest_bytes(wire),
    })
}

#[cfg(test)]
#[path = "business_source_anchor_tests.rs"]
mod tests;
