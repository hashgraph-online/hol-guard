//! Worker-private reusable account. No enrollment, token export or send grant.
use super::{GoogleSendCredential, GrantPurpose};
use crate::{
    worker_input::{GoogleWorkerInput, GoogleWorkerInputError},
    GoogleIdentityEvidence,
};
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

#[path = "account_disconnect.rs"]
mod disconnect;
pub use disconnect::GoogleProjectGrantRevocation;

#[derive(Debug, PartialEq, Eq)]
pub enum GoogleSendAccountError {
    Unavailable,
    IdentityChanged,
}

/// A registered worker may retain this owner across distinct transactions.
/// Each input remains consumable once and still needs native policy/review.
/// No Clone, Debug, serialization, token getter or credential reload exists.
pub struct GoogleSendAccount {
    credential: GoogleSendCredential,
    active: Arc<RwLock<bool>>,
    epoch: String,
}

impl GoogleSendAccount {
    pub fn new(credential: GoogleSendCredential) -> Result<Self, GoogleSendAccountError> {
        if credential.purpose != GrantPurpose::Send
            || !credential.is_current()
            || credential.account_lease.is_some()
        {
            return Err(GoogleSendAccountError::Unavailable);
        }
        Ok(Self {
            epoch: new_epoch()?,
            credential,
            active: Arc::new(RwLock::new(true)),
        })
    }

    pub fn identity(&self) -> &GoogleIdentityEvidence {
        self.credential.identity()
    }

    pub fn is_current(&self) -> bool {
        // A poisoned lease is unavailable. Never recover its value into an
        // admission; revoke() recovers only to force the value to false.
        self.active.read().is_ok_and(|active| *active) && self.credential.is_current()
    }

    pub fn can_refresh(&self) -> bool {
        self.active.read().is_ok_and(|active| *active) && self.credential.can_refresh()
    }

    /// Renew only through registered fixed Google endpoints. Pending inputs
    /// are revoked before exchange; any failure leaves this owner unavailable.
    /// No retry or business send occurs during authorization renewal.
    pub fn refresh(&mut self) -> Result<(), crate::IdentityError> {
        self.refresh_with(|credential| credential.refresh_registered())
    }

    pub(super) fn refresh_with(
        &mut self,
        renew: impl FnOnce(&GoogleSendCredential) -> Result<GoogleSendCredential, crate::IdentityError>,
    ) -> Result<(), crate::IdentityError> {
        self.refresh_with_epoch(renew, new_epoch)
    }

    pub(super) fn refresh_with_epoch(
        &mut self,
        renew: impl FnOnce(&GoogleSendCredential) -> Result<GoogleSendCredential, crate::IdentityError>,
        create_epoch: impl FnOnce() -> Result<String, GoogleSendAccountError>,
    ) -> Result<(), crate::IdentityError> {
        let available = self.can_refresh();
        self.revoke();
        if !available {
            return Err(crate::IdentityError::Invalid);
        }
        let epoch = create_epoch().map_err(|_| crate::IdentityError::Invalid)?;
        let replacement = renew(&self.credential)?;
        if replacement.purpose != GrantPurpose::Send
            || !replacement.is_current()
            || replacement.account_lease.is_some()
            || replacement.identity.account_binding != self.credential.identity.account_binding
            || replacement.identity.tenant_binding != self.credential.identity.tenant_binding
            || !self
                .credential
                .identity
                .sender
                .as_ref()
                .is_some_and(|sender| {
                    replacement
                        .identity
                        .sender
                        .as_ref()
                        .is_some_and(|other| sender.same_mailbox(other))
                })
        {
            return Err(crate::IdentityError::Invalid);
        }
        self.credential = replacement;
        self.active = Arc::new(RwLock::new(true));
        self.epoch = epoch;
        Ok(())
    }

    pub fn prepare_command(
        &self,
        command: String,
    ) -> Result<GoogleWorkerInput, GoogleWorkerInputError> {
        if !self.is_current() {
            return Err(GoogleWorkerInputError::Expired);
        }
        // Only access material is leased; refresh material stays with the owner.
        let identity = &self.credential.identity;
        GoogleSendCredential {
            refresh_registration: None,
            account_lease: Some(Arc::clone(&self.active)),
            account_epoch: Some(self.epoch.clone()),
            purpose: GrantPurpose::Send,
            access_token: Zeroizing::new(self.credential.access_token.as_str().to_owned()),
            refresh_token: None,
            identity: GoogleIdentityEvidence {
                account_binding: identity.account_binding.clone(),
                tenant_binding: identity.tenant_binding.clone(),
                expires_at: identity.expires_at,
                sender: identity.sender.as_ref().map(|sender| sender.worker_copy()),
            },
            expires_at: self.credential.expires_at,
            expires_monotonic: self.credential.expires_monotonic,
        }
        .prepare_command(command)
    }

    /// Replace with fresh worker-verified authorization for this exact account.
    /// Failed replacement leaves the current account intact. Success invalidates
    /// every pending input from the previous epoch.
    pub fn replace(
        &mut self,
        replacement: GoogleSendCredential,
    ) -> Result<(), GoogleSendAccountError> {
        if !self.active.read().is_ok_and(|active| *active)
            || replacement.purpose != GrantPurpose::Send
            || replacement.account_lease.is_some()
            || !replacement.is_current()
        {
            return Err(GoogleSendAccountError::Unavailable);
        }
        if replacement.identity.account_binding != self.credential.identity.account_binding
            || replacement.identity.tenant_binding != self.credential.identity.tenant_binding
            || !self
                .credential
                .identity
                .sender
                .as_ref()
                .is_some_and(|sender| {
                    replacement
                        .identity
                        .sender
                        .as_ref()
                        .is_some_and(|other| sender.same_mailbox(other))
                })
        {
            return Err(GoogleSendAccountError::IdentityChanged);
        }
        // The condition's temporary read guard is already dropped here;
        // revoke takes a fresh write lock, rather than upgrading that guard.
        let epoch = new_epoch()?;
        self.revoke();
        self.credential = replacement;
        self.active = Arc::new(RwLock::new(true));
        self.epoch = epoch;
        Ok(())
    }

    /// Waits for an admitted bounded call, then invalidates pending inputs.
    /// It cannot undo an HTTP call that has already been admitted.
    pub fn revoke(&self) {
        *self
            .active
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
    }
}

fn new_epoch() -> Result<String, GoogleSendAccountError> {
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|_| GoogleSendAccountError::Unavailable)?;
    Ok(hex::encode(random))
}

impl Drop for GoogleSendAccount {
    fn drop(&mut self) {
        self.revoke();
    }
}

#[cfg(test)]
#[path = "account_tests.rs"]
mod tests;
