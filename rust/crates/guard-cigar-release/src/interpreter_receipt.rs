//! Owner-authenticated installed Python metadata; never a remote catalog key.
use crate::{
    types::hex, CatalogCheckpoint, InterpreterBuild, ReleaseError, ResolvedInterpreterBuild,
    TrustedCatalog,
};
use ring::hmac;
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"hol-guard-cigar-local-python-installation.v1\0";
const LIMIT: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledInterpreterReceipt {
    pub schema: String,
    pub build: InterpreterBuild,
    pub catalog_checkpoint: CatalogCheckpoint,
    pub guard_binary_sha256: String,
    pub context_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedInterpreterReceipt {
    pub schema: String,
    pub payload: String,
    pub mac_hex: String,
}
#[derive(Clone, Debug)]
pub struct VerifiedInterpreterReceipt {
    metadata: InstalledInterpreterReceipt,
}
impl VerifiedInterpreterReceipt {
    pub fn metadata(&self) -> &InstalledInterpreterReceipt {
        &self.metadata
    }
    pub fn resolve(
        &self,
        current: &TrustedCatalog,
    ) -> Result<ResolvedInterpreterBuild, ReleaseError> {
        // Catalog omission does not interrupt an already qualified installation.
        if let Some(build) = current
            .document()
            .interpreters
            .iter()
            .find(|build| build.build_id == self.metadata.build.build_id)
        {
            if build.withdrawn {
                return Err(ReleaseError::BuildWithdrawn);
            }
            if build.binding()? != self.metadata.build.binding()? {
                return Err(ReleaseError::IdentityConflict);
            }
        }
        Ok(ResolvedInterpreterBuild::from_installed(
            self.metadata.build.clone(),
            self.metadata.catalog_checkpoint.clone(),
        ))
    }
}
pub fn seal_interpreter_receipt(
    metadata: &InstalledInterpreterReceipt,
    key: &[u8; 32],
) -> Result<SealedInterpreterReceipt, ReleaseError> {
    validate(metadata)?;
    let payload =
        serde_json::to_string(metadata).map_err(|_| ReleaseError::InstallationReceiptInvalid)?;
    if payload.len() > LIMIT {
        return Err(ReleaseError::TooLarge);
    }
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(payload.as_bytes());
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), &message);
    Ok(SealedInterpreterReceipt {
        schema: "guard-cigar-sealed-python-installation.v1".into(),
        payload,
        mac_hex: tag
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}
pub fn verify_interpreter_receipt(
    sealed: &SealedInterpreterReceipt,
    key: &[u8; 32],
    expected_context_sha256: &str,
) -> Result<VerifiedInterpreterReceipt, ReleaseError> {
    if sealed.schema != "guard-cigar-sealed-python-installation.v1"
        || sealed.payload.len() > LIMIT
        || !hex(&sealed.mac_hex, 64)
        || !hex(expected_context_sha256, 64)
    {
        return Err(ReleaseError::InstallationReceiptInvalid);
    }
    let mut tag = [0u8; 32];
    for (index, byte) in tag.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&sealed.mac_hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| ReleaseError::InstallationReceiptInvalid)?;
    }
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(sealed.payload.as_bytes());
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, key), &message, &tag)
        .map_err(|_| ReleaseError::InstallationReceiptUnauthenticated)?;
    let metadata: InstalledInterpreterReceipt =
        crate::strict_json::parse(sealed.payload.as_bytes())
            .map_err(|_| ReleaseError::InstallationReceiptInvalid)?;
    validate(&metadata)?;
    if metadata.context_sha256 != expected_context_sha256 {
        return Err(ReleaseError::InstallationContextMismatch);
    }
    Ok(VerifiedInterpreterReceipt { metadata })
}
fn validate(metadata: &InstalledInterpreterReceipt) -> Result<(), ReleaseError> {
    if metadata.schema != "guard-cigar-installed-python.v1"
        || !hex(&metadata.guard_binary_sha256, 64)
        || !hex(&metadata.context_sha256, 64)
        || !hex(&metadata.catalog_checkpoint.payload_sha256, 64)
        || metadata.catalog_checkpoint.revision == 0
    {
        return Err(ReleaseError::InstallationReceiptInvalid);
    }
    metadata.build.validate()?;
    if metadata.build.withdrawn {
        return Err(ReleaseError::BuildWithdrawn);
    }
    Ok(())
}
