#![forbid(unsafe_code)]

//! Owned business input for the existing native parser and review boundary.
//! This value proves byte commitments only. It does not authenticate account
//! facts, inspect content, authorize an action, or dispatch a provider request.

use guard_contracts::{BusinessActionV1, MAX_BUSINESS_ACTION_ITEMS, MAX_BUSINESS_INLINE_BYTES};
use sha2::{Digest, Sha256};

fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

const PREPARED_INPUT_DOMAIN: &[u8] = b"hol-guard.business-prepared-input.v1\0";
const INPUT_SNAPSHOT_DOMAIN: &[u8] = b"hol-guard.business-input-snapshot.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparedBusinessInputErrorV1 {
    InvalidFacts,
    BoundsExceeded,
    ContentMismatch,
}

fn bounded_total(
    primary: &[u8],
    attachments: &[Vec<u8>],
) -> Result<usize, PreparedBusinessInputErrorV1> {
    if attachments.len() > MAX_BUSINESS_ACTION_ITEMS {
        return Err(PreparedBusinessInputErrorV1::BoundsExceeded);
    }
    attachments
        .iter()
        .try_fold(primary.len(), |total, bytes| {
            total
                .checked_add(bytes.len())
                .filter(|sum| *sum as u128 <= u128::from(MAX_BUSINESS_INLINE_BYTES))
        })
        .filter(|total| *total as u128 <= u128::from(MAX_BUSINESS_INLINE_BYTES))
        .ok_or(PreparedBusinessInputErrorV1::BoundsExceeded)
}

/// Complete frozen-input commitment for native preparation. Hash the domain,
/// primary length and bytes, attachment count, then each attachment length and
/// bytes in order. All lengths/counts are unsigned 64-bit big-endian integers.
/// Length framing prevents different byte partitions from sharing a preimage.
pub fn business_input_snapshot_digest(
    primary: &[u8],
    attachments: &[Vec<u8>],
) -> Result<String, PreparedBusinessInputErrorV1> {
    bounded_total(primary, attachments)?;
    let mut hash = Sha256::new();
    hash.update(INPUT_SNAPSHOT_DOMAIN);
    hash.update((primary.len() as u64).to_be_bytes());
    hash.update(primary);
    hash.update((attachments.len() as u64).to_be_bytes());
    for attachment in attachments {
        hash.update((attachment.len() as u64).to_be_bytes());
        hash.update(attachment);
    }
    Ok(hex::encode(hash.finalize()))
}

/// Deliberately lacks Debug, Serialize, Clone, and mutable accessors: private
/// message and attachment bytes must not enter receipts or generic diagnostics.
/// Preparation transfers ownership; executors must use these bytes rather
/// than reread mutable paths or stdin after approval.
pub struct PreparedBusinessInputV1 {
    facts: BusinessActionV1,
    primary: Box<[u8]>,
    attachments: Vec<Box<[u8]>>,
    binding: String,
}

impl PreparedBusinessInputV1 {
    pub fn prepare(
        facts_json: &[u8],
        primary: Vec<u8>,
        attachments: Vec<Vec<u8>>,
    ) -> Result<Self, PreparedBusinessInputErrorV1> {
        use PreparedBusinessInputErrorV1 as Error;
        // Bound all owned inputs before hashing or constructing commitments.
        let total = bounded_total(&primary, &attachments)?;
        let facts =
            BusinessActionV1::from_bounded_json(facts_json).map_err(|_| Error::InvalidFacts)?;
        facts
            .require_complete_facts()
            .map_err(|_| Error::InvalidFacts)?;
        if facts.content.snapshot_digest != business_input_snapshot_digest(&primary, &attachments)?
            || facts.content.attachment_digests.len() != attachments.len()
            || facts.volume.byte_count != total as u64
            || facts.content.inspected_bytes != total as u64
            || facts
                .content
                .attachment_digests
                .iter()
                .zip(&attachments)
                .any(|(expected, bytes)| *expected != digest_bytes(bytes))
        {
            return Err(Error::ContentMismatch);
        }
        // Typed struct serialization has fixed field order, independent of
        // input key order and serde_json map feature unification. This native
        // preparation commitment is separate from the existing review binding.
        let canonical = serde_json::to_vec(&facts).map_err(|_| Error::InvalidFacts)?;
        let mut preimage = Vec::with_capacity(PREPARED_INPUT_DOMAIN.len() + canonical.len());
        preimage.extend_from_slice(PREPARED_INPUT_DOMAIN);
        preimage.extend_from_slice(&canonical);
        Ok(Self {
            facts,
            primary: primary.into_boxed_slice(),
            attachments: attachments.into_iter().map(Vec::into_boxed_slice).collect(),
            binding: digest_bytes(&preimage),
        })
    }

    pub fn facts(&self) -> &BusinessActionV1 {
        &self.facts
    }
    pub fn primary_bytes(&self) -> &[u8] {
        &self.primary
    }
    pub fn attachments(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.attachments.iter().map(Box::as_ref)
    }
    /// Policy-independent commitment. A review grant must additionally bind
    /// authenticated identity, intent, revision, policy, and dispatch state.
    pub fn binding(&self) -> &str {
        &self.binding
    }
}

#[cfg(test)]
#[path = "business_input_tests.rs"]
mod tests;
