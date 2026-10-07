//! Customer-controlled directory read authorization and private user evidence.
//! No browser/model facts, group expansion or send authority are accepted.

use crate::oauth::{GoogleSendAuthorization, GoogleSendCredential};
use crate::outbound::InspectedGoogleWorkerInput;
use crate::{binding, bounded_ascii, GoogleIdentityEvidence, GoogleLoginChallenge, IdentityError};
use guard_contracts::BusinessRecipientKindV1;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[path = "directory_prepared.rs"]
mod prepared;
pub use prepared::PreparedGoogleBusinessRequest;

#[derive(Debug, PartialEq, Eq)]
pub enum DirectoryError {
    Expired,
    TenantMismatch,
    Invalid,
    Unresolved,
    Unavailable,
}

pub struct GoogleDirectoryAuthorization {
    pending: GoogleSendAuthorization,
    customer_id: String,
    namespace_key: Zeroizing<[u8; 32]>,
}
pub struct GoogleDirectoryCredential {
    credential: GoogleSendCredential,
    customer_id: String,
    namespace_key: Zeroizing<[u8; 32]>,
}

impl GoogleDirectoryAuthorization {
    /// All configuration, including the customer ID, comes from the registered
    /// customer worker. This is a separate read grant, never a send grant.
    pub fn begin(
        challenge: GoogleLoginChallenge,
        secret: String,
        redirect: String,
        authenticated_session: String,
        registered_customer_id: String,
    ) -> Result<Self, IdentityError> {
        if !bounded_ascii(&registered_customer_id, 64)
            || !registered_customer_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric())
        {
            return Err(IdentityError::Invalid);
        }
        let namespace_key = Zeroizing::new(challenge.namespace_key);
        let pending = GoogleSendAuthorization::begin_directory(
            challenge,
            secret,
            redirect,
            authenticated_session,
        )?;
        Ok(Self {
            pending,
            customer_id: registered_customer_id,
            namespace_key,
        })
    }
    pub fn authorization_url(&self) -> &str {
        self.pending.authorization_url()
    }
    pub fn complete(
        self,
        state: &str,
        code: String,
        authenticated_session: &str,
    ) -> Result<GoogleDirectoryCredential, IdentityError> {
        Ok(GoogleDirectoryCredential {
            credential: self.pending.complete(state, code, authenticated_session)?,
            customer_id: self.customer_id,
            namespace_key: self.namespace_key,
        })
    }
}

pub struct ResolvedGoogleRecipient {
    address: String,
    kind: BusinessRecipientKindV1,
    principal_binding: String,
}
impl ResolvedGoogleRecipient {
    pub fn address(&self) -> &str {
        &self.address
    }
    pub fn kind(&self) -> BusinessRecipientKindV1 {
        self.kind
    }
    pub fn principal_binding(&self) -> &str {
        &self.principal_binding
    }
}
pub struct ResolvedGoogleWorkerInput {
    directory: GoogleDirectoryCredential,
    input: InspectedGoogleWorkerInput,
    recipients: Vec<ResolvedGoogleRecipient>,
    resolution_binding: String,
    deadline: Instant,
}
impl ResolvedGoogleWorkerInput {
    pub fn refresh(self) -> Result<Self, DirectoryError> {
        self.directory.resolve_owned_input(self.input)
    }
    pub fn input(&self) -> &InspectedGoogleWorkerInput {
        &self.input
    }
    pub fn recipients(&self) -> &[ResolvedGoogleRecipient] {
        &self.recipients
    }
    pub fn resolution_binding(&self) -> &str {
        &self.resolution_binding
    }
    pub fn is_current(&self) -> bool {
        Instant::now() < self.deadline
            && self.directory.credential.is_current()
            && self.input.input().is_current()
    }
}

impl GoogleDirectoryCredential {
    pub fn identity(&self) -> &GoogleIdentityEvidence {
        self.credential.identity()
    }
    /// Consume the directory grant and inspected input together. Named users
    /// only; groups and inaccessible/ambiguous rows are unresolved, not guessed.
    /// This pilot supports at most eight recipient entries with a strict
    /// 15-second freshness budget; slow lookup fails closed. Multiple literal
    /// aliases of one principal are unresolved until canonical audience support.
    pub fn resolve_owned_input(
        self,
        input: InspectedGoogleWorkerInput,
    ) -> Result<ResolvedGoogleWorkerInput, DirectoryError> {
        self.resolve_with(input, |credential, address| {
            credential.directory_user(address)
        })
    }
    fn resolve_with(
        self,
        input: InspectedGoogleWorkerInput,
        mut lookup: impl FnMut(
            &GoogleSendCredential,
            &str,
        ) -> Result<Zeroizing<Vec<u8>>, DirectoryError>,
    ) -> Result<ResolvedGoogleWorkerInput, DirectoryError> {
        if self.identity().tenant_binding() != input.input().identity().tenant_binding() {
            return Err(DirectoryError::TenantMismatch);
        }
        if input.input().input().recipients().len() > 8 {
            return Err(DirectoryError::Unresolved);
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        let current = || {
            self.credential.is_current() && input.input().is_current() && Instant::now() < deadline
        };
        if !current() {
            return Err(DirectoryError::Expired);
        }
        let sender = input.input().input().sender();
        let sender_bytes = lookup(&self.credential, sender)?;
        let sender_user = User::from_bytes(&sender_bytes, sender, &self.customer_id)?;
        let mut hash = Sha256::new();
        hash.update(b"hol-guard.google-directory-resolution.v1\0");
        let customer_binding = binding(
            &self.namespace_key,
            b"hol-guard.google-directory-customer.v1\0",
            &[self.identity().tenant_binding(), &self.customer_id],
        );
        for field in [
            input.inspection_binding(),
            &customer_binding,
            self.identity().account_binding(),
            &sender_user.id,
            &sender_user.etag,
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        let mut recipients = Vec::new();
        let mut principal_addresses = std::collections::BTreeMap::new();
        for literal in input.input().input().recipients() {
            if !current() {
                return Err(DirectoryError::Expired);
            }
            let bytes = lookup(&self.credential, literal.address())?;
            let user = User::from_bytes(&bytes, literal.address(), &self.customer_id)?;
            let principal_binding = binding(
                &self.namespace_key,
                b"hol-guard.google-directory-user.v1\0",
                &[&customer_binding, &user.id],
            );
            if principal_addresses
                .insert(principal_binding.clone(), literal.address())
                .is_some_and(|previous| previous != literal.address())
            {
                return Err(DirectoryError::Unresolved);
            }
            for field in [literal.address(), &principal_binding, &user.etag] {
                hash.update((field.len() as u64).to_be_bytes());
                hash.update(field.as_bytes());
            }
            hash.update([match literal.kind() {
                BusinessRecipientKindV1::To => 0,
                BusinessRecipientKindV1::Cc => 1,
                BusinessRecipientKindV1::Bcc => 2,
                // Drive collaborators and Calendar attendees require another
                // operation profile, never implicit conversion to mail recipients.
                _ => return Err(DirectoryError::Invalid),
            }]);
            recipients.push(ResolvedGoogleRecipient {
                address: literal.address().into(),
                kind: literal.kind(),
                principal_binding,
            });
        }
        if !current() {
            return Err(DirectoryError::Expired);
        }
        Ok(ResolvedGoogleWorkerInput {
            directory: self,
            input,
            recipients,
            resolution_binding: hex::encode(hash.finalize()),
            deadline,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct User {
    kind: String,
    id: String,
    primary_email: String,
    customer_id: String,
    suspended: bool,
    etag: String,
    #[serde(default)]
    archived: bool,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    non_editable_aliases: Vec<String>,
}
impl User {
    fn from_bytes(bytes: &[u8], requested: &str, customer: &str) -> Result<Self, DirectoryError> {
        if bytes.len() > 64 * 1024 {
            return Err(DirectoryError::Invalid);
        }
        let user: Self = serde_json::from_slice(bytes).map_err(|_| DirectoryError::Invalid)?;
        if user.customer_id != customer {
            return Err(DirectoryError::TenantMismatch);
        }
        if user.kind != "admin#directory#user"
            || !bounded_ascii(&user.id, 255)
            || !bounded_ascii(&user.etag, 512)
            || user.suspended
            || user.archived
            || !crate::sender::supported_mailbox(&user.primary_email)
            || user.aliases.len() + user.non_editable_aliases.len() > 256
        {
            return Err(DirectoryError::Unresolved);
        }
        let mut aliases = BTreeSet::new();
        for alias in user.aliases.iter().chain(&user.non_editable_aliases) {
            if !crate::sender::supported_mailbox(alias) || !aliases.insert(alias.as_str()) {
                return Err(DirectoryError::Unresolved);
            }
        }
        if requested != user.primary_email && !aliases.contains(requested) {
            return Err(DirectoryError::Unresolved);
        }
        Ok(user)
    }
}

#[cfg(test)]
#[path = "directory_tests.rs"]
mod tests;
