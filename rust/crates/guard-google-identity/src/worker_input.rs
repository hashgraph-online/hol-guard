//! Worker-owned command, MIME and signed sender pairing. Preparation is not
//! policy admission, recipient resolution, approval or an execution grant.

use crate::oauth::GoogleSendCredential;
use crate::GoogleIdentityEvidence;
use guard_command::business_gmail_plain::GmailPlainInputV1;
use guard_command::business_gws_command::GwsGmailSendCommandInputV1;
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, Eq)]
pub enum GoogleWorkerInputError {
    Expired,
    Command,
    Mime,
    Sender,
}

/// Owns the credential and immutable provider bytes together. No Clone,
/// Debug, serialization, mutable access, credential export or send method.
pub struct GoogleWorkerInput {
    credential: GoogleSendCredential,
    input: GmailPlainInputV1,
    binding: String,
}

impl GoogleSendCredential {
    /// Consume the credential and original command; never execute the shell
    /// source after approval. Only the existing narrow inline profile is read.
    pub fn prepare_command(
        self,
        command: String,
    ) -> Result<GoogleWorkerInput, GoogleWorkerInputError> {
        if !self.is_current() {
            return Err(GoogleWorkerInputError::Expired);
        }
        let command = GwsGmailSendCommandInputV1::from_owned_posix_command(command)
            .map_err(|_| GoogleWorkerInputError::Command)?;
        let command_binding = command.input_binding().to_owned();
        let input = GmailPlainInputV1::from_owned_wire(command.into_wire_input())
            .map_err(|_| GoogleWorkerInputError::Mime)?;
        if !self.is_current() {
            return Err(GoogleWorkerInputError::Expired);
        }
        if !self.sender_matches(input.sender()) {
            return Err(GoogleWorkerInputError::Sender);
        }
        let mut digest = Sha256::new();
        digest.update(b"hol-guard.google-worker-input.v1\0");
        for field in [
            self.identity().account_binding(),
            self.identity().tenant_binding(),
            &command_binding,
            input.input_binding(),
        ] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field.as_bytes());
        }
        Ok(GoogleWorkerInput {
            credential: self,
            input,
            binding: hex::encode(digest.finalize()),
        })
    }
}

impl GoogleWorkerInput {
    pub(crate) fn send_once(
        self,
        bytes: &[u8],
    ) -> Result<crate::dispatch::RawSendAttempt, crate::dispatch::GoogleDispatchError> {
        if bytes != self.input.wire_input().body_bytes() {
            return Err(crate::dispatch::GoogleDispatchError::InputChanged);
        }
        self.credential.send_json_once(bytes)
    }
    pub fn identity(&self) -> &GoogleIdentityEvidence {
        self.credential.identity()
    }
    /// Private local inspection only; these bytes and addresses must not be
    /// serialized into Cloud metadata or surfaced to the model as authority.
    pub fn input(&self) -> &GmailPlainInputV1 {
        &self.input
    }
    pub fn input_binding(&self) -> &str {
        &self.binding
    }
    pub fn is_current(&self) -> bool {
        self.credential.authenticates_sender(self.input.sender())
    }
}
