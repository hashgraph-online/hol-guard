//! Aggregate dispatch observations, never authorization or proof of final effect.
use serde::{Deserialize, Serialize};

pub const NATIVE_BUSINESS_DISPATCH_RECEIPT_V1_SCHEMA: &str =
    "guard-native-business-dispatch-receipt.v1";
pub const NATIVE_BUSINESS_DISPATCH_RECEIPT_MAX_BYTES: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BusinessDispatchAttemptV1 {
    ApiAccepted,
    OutcomeUnknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BusinessDispatchJournalV1 {
    Recorded,
    Unconfirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BusinessProviderEffectV1 {
    NotChecked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BusinessDispatchRetryAuthorityV1 {
    None,
}

/// The opaque bindings correlate observations with an existing consumed decision
/// and frozen input. Neither this unsigned receipt nor an API acknowledgement
/// authorizes dispatch, restores an owned handle, or confirms delivery.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NativeBusinessDispatchReceiptV1 {
    pub schema: String,
    pub version: u16,
    pub decision_binding: String,
    pub input_binding: String,
    pub attempt: BusinessDispatchAttemptV1,
    pub journal: BusinessDispatchJournalV1,
    pub provider_effect: BusinessProviderEffectV1,
    pub retry_authority: BusinessDispatchRetryAuthorityV1,
    pub acknowledgement_binding: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptWire {
    schema: String,
    version: u16,
    decision_binding: String,
    input_binding: String,
    attempt: BusinessDispatchAttemptV1,
    journal: BusinessDispatchJournalV1,
    provider_effect: BusinessProviderEffectV1,
    retry_authority: BusinessDispatchRetryAuthorityV1,
    acknowledgement_binding: Option<String>,
}

/// Decode original bytes before allocating JSON strings. The public receipt
/// deliberately has no generic Deserialize implementation: use this bounded
/// entry point, not an already parsed caller-controlled JSON value.
pub fn parse_native_business_dispatch_receipt(
    bytes: &[u8],
) -> Result<NativeBusinessDispatchReceiptV1, &'static str> {
    if bytes.len() > NATIVE_BUSINESS_DISPATCH_RECEIPT_MAX_BYTES {
        return Err("native_business_dispatch_receipt_too_large");
    }
    let wire: ReceiptWire =
        serde_json::from_slice(bytes).map_err(|_| "native_business_dispatch_receipt_invalid")?;
    wire.try_into()
}

impl TryFrom<ReceiptWire> for NativeBusinessDispatchReceiptV1 {
    type Error = &'static str;
    fn try_from(v: ReceiptWire) -> Result<Self, Self::Error> {
        let receipt = Self {
            schema: v.schema,
            version: v.version,
            decision_binding: v.decision_binding,
            input_binding: v.input_binding,
            attempt: v.attempt,
            journal: v.journal,
            provider_effect: v.provider_effect,
            retry_authority: v.retry_authority,
            acknowledgement_binding: v.acknowledgement_binding,
        };
        receipt.validate()?;
        Ok(receipt)
    }
}

impl NativeBusinessDispatchReceiptV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        fn digest(s: &str) -> bool {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        if self.schema != NATIVE_BUSINESS_DISPATCH_RECEIPT_V1_SCHEMA
            || self.version != 1
            || !digest(&self.decision_binding)
            || !digest(&self.input_binding)
            || (self.attempt == BusinessDispatchAttemptV1::ApiAccepted)
                != self.acknowledgement_binding.is_some()
            || self
                .acknowledgement_binding
                .as_deref()
                .is_some_and(|s| !digest(s))
        {
            return Err("native_business_dispatch_receipt_invalid");
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "business_dispatch_receipt_tests.rs"]
mod tests;
