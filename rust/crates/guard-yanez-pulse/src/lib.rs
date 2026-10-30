#![forbid(unsafe_code)]
//! Yanez Pulse as a HOL Guard approval-gate factor.
//!
//! A Pulse receipt authorizes nothing by itself. This crate owns everything
//! Guard checks before it treats a receipt as an approval:
//!
//! - the outer receipt, a compact EdDSA JWS signed by Yanez (`jws`),
//! - the approver's BLS12-381 signature over the decision envelope (`user_sig`),
//! - the exact Guard action the terms were built from (`terms`),
//! - the pinned YID, issuer, agent key, assurance floor and freshness
//!   window (`receipt`).
//!
//! `client` is the HTTPS transport to the Pulse service. The caller owns the
//! agent key, the single-use ledger and the grant table; nothing here holds a
//! lock across a network call.

pub mod client;
pub mod jws;
pub mod receipt;
pub mod strict_json;
pub mod terms;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
pub mod user_sig;

use std::fmt;

/// Yanez assurance tier the approver's biometric scan reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssuranceTier {
    Low,
    Medium,
    High,
}

impl AssuranceTier {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    /// Tiers Guard accepts as an approval floor. `low` is never accepted as
    /// an approval-gate factor.
    pub fn is_allowed_floor(self) -> bool {
        matches!(self, Self::Medium | Self::High)
    }
}

/// Every way a Pulse approval can fail. Each one leaves the action blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PulseError {
    /// The receipt is malformed or its Yanez signature does not verify.
    ReceiptInvalid(&'static str),
    /// The receipt names a Yanez signing key Guard does not know.
    UnknownSigningKey,
    /// The approver's BLS signature or its envelope does not verify.
    UserSignatureInvalid(&'static str),
    /// The receipt was issued by a different Yanez deployment.
    WrongIssuer,
    /// The receipt was approved by a different YID than the pinned one.
    WrongYid,
    /// The receipt was requested by a different agent key.
    WrongAgentKey,
    /// The receipt is for a different Pulse request.
    WrongRequest,
    /// The approved terms are not the terms Guard sent for this action.
    TermsMismatch,
    /// The scan reached a lower tier than Guard accepts.
    AssuranceTooLow,
    /// The approver's key is not registered to the pinned YID at that tier.
    UserKeyNotRegistered,
    /// The decision is older than Guard's freshness window.
    Stale,
    /// The consent bound on the receipt has passed.
    ConsentExpired,
    /// The receipt was already used.
    Replayed,
    /// The user rejected the request in the YID app.
    Rejected,
    /// The request expired before the user decided.
    Expired,
    /// Pulse refused the agent key (revoked or unknown).
    AgentKeyRejected,
    /// Pulse could not be reached or answered unexpectedly.
    Unavailable,
    /// The caller passed something Guard refuses to send to Pulse.
    InvalidRequest(&'static str),
}

impl PulseError {
    /// Stable approval-gate error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ReceiptInvalid(_) | Self::UnknownSigningKey => {
                "approval_gate_pulse_receipt_invalid"
            }
            Self::UserSignatureInvalid(_) => "approval_gate_pulse_user_signature_invalid",
            Self::WrongIssuer => "approval_gate_pulse_wrong_issuer",
            Self::WrongYid => "approval_gate_pulse_wrong_yid",
            Self::WrongAgentKey => "approval_gate_pulse_wrong_agent_key",
            Self::WrongRequest => "approval_gate_pulse_wrong_request",
            Self::TermsMismatch => "approval_gate_pulse_terms_mismatch",
            Self::AssuranceTooLow => "approval_gate_pulse_assurance_too_low",
            Self::UserKeyNotRegistered => "approval_gate_pulse_user_key_unregistered",
            Self::Stale => "approval_gate_pulse_stale",
            Self::ConsentExpired => "approval_gate_pulse_consent_expired",
            Self::Replayed => "approval_gate_pulse_replayed",
            Self::Rejected => "approval_gate_pulse_rejected",
            Self::Expired => "approval_gate_pulse_expired",
            Self::AgentKeyRejected => "approval_gate_pulse_agent_key_rejected",
            Self::Unavailable => "approval_gate_pulse_unavailable",
            Self::InvalidRequest(_) => "approval_gate_pulse_invalid_request",
        }
    }

    /// HTTP-ish status, matching the approval gate's conventions.
    pub fn status(&self) -> u16 {
        match self {
            Self::Unavailable => 503,
            Self::AgentKeyRejected => 423,
            Self::InvalidRequest(_) => 400,
            _ => 403,
        }
    }

    /// Message safe to show the user. Never contains receipt or key material.
    pub fn message(&self) -> &'static str {
        match self {
            Self::ReceiptInvalid(_) | Self::UnknownSigningKey => {
                "The Pulse receipt could not be verified."
            }
            Self::UserSignatureInvalid(_) => "The approver's signature could not be verified.",
            Self::WrongIssuer => "The Pulse receipt came from an unexpected Yanez deployment.",
            Self::WrongYid => "The Pulse approval came from a different Yanez identity.",
            Self::WrongAgentKey => "The Pulse approval was requested by a different agent key.",
            Self::WrongRequest => "The Pulse receipt is for a different request.",
            Self::TermsMismatch => "The Pulse approval does not match the held action.",
            Self::AssuranceTooLow => {
                "Your scan in the YID app did not reach the assurance tier Guard requires. Try again."
            }
            Self::UserKeyNotRegistered => {
                "The approving device key is not registered to your Yanez identity."
            }
            Self::Stale => "The Pulse approval is too old. Approve the action again.",
            Self::ConsentExpired => "The Pulse approval window has closed. Approve again.",
            Self::Replayed => "That Pulse approval was already used.",
            Self::Rejected => "The action was rejected in the YID app.",
            Self::Expired => "The Pulse request expired before it was approved.",
            Self::AgentKeyRejected => {
                "Pulse refused Guard's agent key. Re-enroll Pulse or use recovery."
            }
            Self::Unavailable => "Yanez Pulse is unreachable. The action stays blocked.",
            Self::InvalidRequest(_) => "The Pulse request is invalid.",
        }
    }
}

impl fmt::Display for PulseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for PulseError {}
