//! Derive native business facts from owned verified input, never caller JSON.

use super::{DirectoryError, ResolvedGoogleWorkerInput};
use crate::binding;
use guard_command::business_gmail_wire::GWS_GMAIL_SEND_SCHEMA_DIGEST;
use guard_command::business_input::{business_input_snapshot_digest, PreparedBusinessInputV1};
use guard_contracts::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[path = "directory_dispatch.rs"]
mod dispatch;

pub struct PreparedGoogleBusinessRequest {
    resolved: ResolvedGoogleWorkerInput,
    prepared: PreparedBusinessInputV1,
}
impl PreparedGoogleBusinessRequest {
    pub fn prepared_input(&self) -> &PreparedBusinessInputV1 {
        &self.prepared
    }
    pub fn is_current(&self) -> bool {
        self.resolved.is_current()
    }
    pub fn resolution_binding(&self) -> &str {
        self.resolved.resolution_binding()
    }
    /// Re-resolve against the provider before dispatch. A changed revision
    /// changes prepared facts/binding and cannot match the old approval input.
    pub fn refresh(self) -> Result<Self, DirectoryError> {
        self.resolved.refresh()?.prepare_business_request()
    }
}
fn digest(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hex::encode(hash.finalize())
}
impl ResolvedGoogleWorkerInput {
    pub fn prepare_business_request(self) -> Result<PreparedGoogleBusinessRequest, DirectoryError> {
        if !self.is_current() {
            return Err(DirectoryError::Expired);
        }
        let worker = self.input().input();
        let body = worker.input().wire_input().body_bytes().to_vec();
        let snapshot =
            business_input_snapshot_digest(&body, &[]).map_err(|_| DirectoryError::Invalid)?;
        let mut recipients = Vec::new();
        for recipient in self.recipients() {
            // Resolution refuses multiple literal aliases of one principal.
            // Keep exact address/domain facts bound; repeating an identical
            // mailbox across To/Cc/Bcc counts it once below.
            let identity_binding = binding(
                &self.directory.namespace_key,
                b"hol-guard.google-resolved-mailbox.v1\0",
                &[recipient.principal_binding(), recipient.address()],
            );
            let domain = recipient
                .address()
                .rsplit_once('@')
                .ok_or(DirectoryError::Invalid)?
                .1
                .to_owned();
            recipients.push(BusinessRecipientV1 {
                identity_binding,
                domain,
                kind: recipient.kind(),
            });
        }
        let count = recipients
            .iter()
            .map(|r| &r.identity_binding)
            .collect::<BTreeSet<_>>()
            .len() as u64;
        let facts = BusinessActionV1 {
            schema: BUSINESS_ACTION_V1_SCHEMA.into(),
            version: BUSINESS_ACTION_V1_VERSION,
            provider: BusinessProviderV1 {
                service: BusinessServiceV1::GoogleGmail,
                account_binding: Some(worker.identity().account_binding().into()),
                tenant_binding: Some(worker.identity().tenant_binding().into()),
                identity_state: BusinessFactStateV1::Known,
                tool_identity_digest: digest(
                    b"hol-guard.google-owned-api.v1\0",
                    &[b"POST", crate::dispatch::GMAIL_SEND_URL.as_bytes()],
                ),
                tool_schema_digest: GWS_GMAIL_SEND_SCHEMA_DIGEST.into(),
            },
            operation: BusinessOperationV1::MailSend,
            audience: BusinessAudienceV1 {
                kind: BusinessAudienceKindV1::Named,
                expansion_state: BusinessFactStateV1::Known,
                recipients,
            },
            content: BusinessContentV1 {
                snapshot_digest: snapshot,
                attachment_digests: vec![],
                inspection_state: BusinessFactStateV1::Known,
                inspected_bytes: body.len() as u64,
                // Every work message contains private account/audience data.
                // Never infer Public from absence of a credential finding.
                sensitivity_labels: vec![
                    BusinessSensitivityV1::Personal,
                    BusinessSensitivityV1::Confidential,
                ],
            },
            target: BusinessTargetV1 {
                resource_binding: digest(
                    b"hol-guard.google-mail-resource.v1\0",
                    &[
                        worker.identity().account_binding().as_bytes(),
                        b"users/me/messages",
                    ],
                ),
                revision_binding: self.resolution_binding().into(),
                field_diff_digest: digest(b"hol-guard.google-mail-create.v1\0", &[&body]),
                batch_manifest_digest: digest(
                    b"hol-guard.google-mail-batch.v1\0",
                    &[
                        worker.input_binding().as_bytes(),
                        self.resolution_binding().as_bytes(),
                    ],
                ),
            },
            volume: BusinessVolumeV1 {
                recipient_count: count,
                record_count: 1,
                byte_count: body.len() as u64,
            },
            completeness: BusinessFactStateV1::Known,
        };
        let facts_bytes = serde_json::to_vec(&facts).map_err(|_| DirectoryError::Invalid)?;
        let prepared = PreparedBusinessInputV1::prepare(&facts_bytes, body, vec![])
            .map_err(|_| DirectoryError::Invalid)?;
        if !self.is_current() {
            return Err(DirectoryError::Expired);
        }
        Ok(PreparedGoogleBusinessRequest {
            resolved: self,
            prepared,
        })
    }
}
