//! Canonical, bounded prelaunch pin/ack frames. The worker must not start the
//! controller until a host has durably recorded these pins and returned an ack.

use crate::{canonicalize, is_git_sha};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;

const PREPARED_SCHEMA: &str = "hol-gauntlet-controller-prepared.v1";
const ACK_SCHEMA: &str = "hol-gauntlet-controller-prelaunch-ack.v1";
const HOST_PIN_SCHEMA: &str = "hol-gauntlet-host-controller-key-pin.v1";
const MAX_FRAME_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrelaunchHandoffError {
    InvalidPins,
    InvalidPrepared,
    InvalidAck,
}

impl fmt::Display for PrelaunchHandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPins => "invalid controller prelaunch identity",
            Self::InvalidPrepared => "controller prelaunch frame is malformed or noncanonical",
            Self::InvalidAck => "host prelaunch acknowledgement differs from prepared pins",
        })
    }
}

impl std::error::Error for PrelaunchHandoffError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrelaunchPrepared {
    pub job_id: String,
    pub source_sha: String,
    pub deployment_digest: String,
    pub worker_generation: String,
    pub started_marker_sha256: String,
    pub controller_key_pin_sha256: String,
    pub controller_public_key_hex: String,
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded_canonical(value: &Value) -> Result<Vec<u8>, PrelaunchHandoffError> {
    let bytes = canonicalize(value.to_string().as_bytes())
        .map_err(|_| PrelaunchHandoffError::InvalidPins)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(PrelaunchHandoffError::InvalidPins);
    }
    Ok(bytes)
}

impl PrelaunchPrepared {
    fn valid(&self) -> bool {
        hex(&self.job_id, 16)
            && is_git_sha(&self.source_sha)
            && hex(&self.deployment_digest, 64)
            && hex(&self.worker_generation, 64)
            && hex(&self.started_marker_sha256, 64)
            && hex(&self.controller_key_pin_sha256, 64)
            && hex(&self.controller_public_key_hex, 64)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, PrelaunchHandoffError> {
        if !self.valid() {
            return Err(PrelaunchHandoffError::InvalidPins);
        }
        bounded_canonical(&json!({
            "schema":PREPARED_SCHEMA,
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "deployment_digest":self.deployment_digest,
            "worker_generation":self.worker_generation,
            "started_marker_sha256":self.started_marker_sha256,
            "controller_key_pin_sha256":self.controller_key_pin_sha256,
            "controller_public_key_hex":self.controller_public_key_hex,
        }))
    }

    pub fn parse(raw: &[u8]) -> Result<Self, PrelaunchHandoffError> {
        if raw.is_empty() || raw.len() > MAX_FRAME_BYTES {
            return Err(PrelaunchHandoffError::InvalidPrepared);
        }
        if canonicalize(raw).map_err(|_| PrelaunchHandoffError::InvalidPrepared)? != raw {
            return Err(PrelaunchHandoffError::InvalidPrepared);
        }
        let value: Value =
            serde_json::from_slice(raw).map_err(|_| PrelaunchHandoffError::InvalidPrepared)?;
        let object = value
            .as_object()
            .ok_or(PrelaunchHandoffError::InvalidPrepared)?;
        let string = |name| {
            value[name]
                .as_str()
                .map(str::to_owned)
                .ok_or(PrelaunchHandoffError::InvalidPrepared)
        };
        if object.len() != 8 || value["schema"] != PREPARED_SCHEMA {
            return Err(PrelaunchHandoffError::InvalidPrepared);
        }
        let prepared = Self {
            job_id: string("job_id")?,
            source_sha: string("source_sha")?,
            deployment_digest: string("deployment_digest")?,
            worker_generation: string("worker_generation")?,
            started_marker_sha256: string("started_marker_sha256")?,
            controller_key_pin_sha256: string("controller_key_pin_sha256")?,
            controller_public_key_hex: string("controller_public_key_hex")?,
        };
        if !prepared.valid() || prepared.to_bytes().ok().as_deref() != Some(raw) {
            return Err(PrelaunchHandoffError::InvalidPrepared);
        }
        Ok(prepared)
    }

    pub fn host_record_sha256(&self) -> Result<String, PrelaunchHandoffError> {
        self.to_bytes()?;
        let bytes = bounded_canonical(&json!({
            "schema":HOST_PIN_SCHEMA,
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "deployment_digest":self.deployment_digest,
            "worker_generation":self.worker_generation,
            "started_marker_sha256":self.started_marker_sha256,
            "controller_key_pin_sha256":self.controller_key_pin_sha256,
            "controller_public_key_hex":self.controller_public_key_hex,
        }))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    /// The host calls this only after its exclusive pin record has been
    /// fsynced and reread. The worker compares the returned ack before spawn.
    pub fn acknowledgement(
        &self,
        durable_host_record_sha256: &str,
    ) -> Result<Vec<u8>, PrelaunchHandoffError> {
        if durable_host_record_sha256 != self.host_record_sha256()? {
            return Err(PrelaunchHandoffError::InvalidAck);
        }
        let prepared = self.to_bytes()?;
        bounded_canonical(&json!({
            "schema":ACK_SCHEMA,
            "job_id":self.job_id,
            "prepared_sha256":format!("{:x}", Sha256::digest(prepared)),
            "host_pin_record_sha256":durable_host_record_sha256,
        }))
    }

    pub fn verify_acknowledgement(&self, raw: &[u8]) -> Result<(), PrelaunchHandoffError> {
        if raw.is_empty() || raw.len() > MAX_FRAME_BYTES {
            return Err(PrelaunchHandoffError::InvalidAck);
        }
        if canonicalize(raw).map_err(|_| PrelaunchHandoffError::InvalidAck)? != raw {
            return Err(PrelaunchHandoffError::InvalidAck);
        }
        let value: Value =
            serde_json::from_slice(raw).map_err(|_| PrelaunchHandoffError::InvalidAck)?;
        if value.as_object().is_none_or(|object| object.len() != 4)
            || value["schema"] != ACK_SCHEMA
            || value["job_id"] != self.job_id
            || value["host_pin_record_sha256"] != self.host_record_sha256()?
            || value["prepared_sha256"] != format!("{:x}", Sha256::digest(self.to_bytes()?))
        {
            return Err(PrelaunchHandoffError::InvalidAck);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepared() -> PrelaunchPrepared {
        PrelaunchPrepared {
            job_id: "a".repeat(16),
            source_sha: "b".repeat(40),
            deployment_digest: "c".repeat(64),
            worker_generation: "d".repeat(64),
            started_marker_sha256: "e".repeat(64),
            controller_key_pin_sha256: "f".repeat(64),
            controller_public_key_hex: "0".repeat(64),
        }
    }

    #[test]
    fn exact_prepared_and_ack_round_trip() {
        let pins = prepared();
        let raw = pins.to_bytes().unwrap();
        assert_eq!(PrelaunchPrepared::parse(&raw), Ok(pins.clone()));
        let ack = pins
            .acknowledgement(&pins.host_record_sha256().unwrap())
            .unwrap();
        assert_eq!(pins.verify_acknowledgement(&ack), Ok(()));
    }

    #[test]
    fn changed_or_ambiguous_frames_refuse() {
        let pins = prepared();
        let mut changed = pins.clone();
        changed.controller_public_key_hex = "1".repeat(64);
        let ack = pins
            .acknowledgement(&pins.host_record_sha256().unwrap())
            .unwrap();
        assert_eq!(
            changed.verify_acknowledgement(&ack),
            Err(PrelaunchHandoffError::InvalidAck)
        );
        assert!(PrelaunchPrepared::parse(b"{}").is_err());
        assert!(PrelaunchPrepared::parse(&[b' '; 1025]).is_err());
        let duplicate = raw_duplicate_schema();
        assert_eq!(
            PrelaunchPrepared::parse(&duplicate),
            Err(PrelaunchHandoffError::InvalidPrepared)
        );
    }

    fn raw_duplicate_schema() -> Vec<u8> {
        let raw = prepared().to_bytes().unwrap();
        let mut duplicate = b"{\"schema\":\"hol-gauntlet-controller-prepared.v1\",".to_vec();
        duplicate.extend_from_slice(&raw[1..]);
        duplicate
    }
}
