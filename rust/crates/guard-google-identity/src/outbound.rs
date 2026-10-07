//! Credential inspection for private outbound input, using the existing native
//! scanner. A clean scan is not a public classification or general DLP proof.

use crate::worker_input::GoogleWorkerInput;
use guard_scanner::secret_detection::scan_secret_text;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(Debug, PartialEq, Eq)]
pub enum OutboundInspectionError {
    Expired,
    UnsupportedEncoding,
    CredentialDetected,
}

/// Owns the inspected input. No serialization, Clone, Debug, mutable access,
/// approval or send method. Only the private native worker should consume it.
pub struct InspectedGoogleWorkerInput {
    input: GoogleWorkerInput,
    inspection_binding: String,
    detector_version: String,
}

impl GoogleWorkerInput {
    /// Inspect all original MIME headers/wire text and the decoded text body.
    /// This bounded profile accepts UTF-8 and unencoded header text only;
    /// unsupported charsets and RFC 2047 words cannot obtain a clean scan.
    /// No lossy decoding, caller-supplied finding, network or model call.
    pub fn inspect_outbound(self) -> Result<InspectedGoogleWorkerInput, OutboundInspectionError> {
        if !self.is_current() {
            return Err(OutboundInspectionError::Expired);
        }
        let wire = self.input().wire_input().mime_bytes();
        let boundary = wire
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or(OutboundInspectionError::UnsupportedEncoding)?;
        if wire[..boundary].windows(2).any(|w| w == b"=?") {
            return Err(OutboundInspectionError::UnsupportedEncoding);
        }
        let mut version = None;
        for bytes in [
            self.input().wire_input().mime_bytes(),
            self.input().body_bytes(),
        ] {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| OutboundInspectionError::UnsupportedEncoding)?;
            let mut summary = scan_secret_text(text, "", "business-outbound", None, 1);
            let found = !summary.findings.is_empty();
            // Candidate strings are private detector scratch, never telemetry.
            for finding in &mut summary.findings {
                finding.candidate.zeroize();
            }
            if found {
                return Err(OutboundInspectionError::CredentialDetected);
            }
            version = Some(summary.detector_version);
        }
        if !self.is_current() {
            return Err(OutboundInspectionError::Expired);
        }
        let detector_version = version.expect("two bounded input views inspected");
        let mut hash = Sha256::new();
        hash.update(b"hol-guard.google-outbound-inspection.v1\0");
        for field in [self.input_binding(), detector_version.as_str()] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        Ok(InspectedGoogleWorkerInput {
            input: self,
            inspection_binding: hex::encode(hash.finalize()),
            detector_version,
        })
    }
}

impl InspectedGoogleWorkerInput {
    pub(crate) fn into_input(self) -> GoogleWorkerInput {
        self.input
    }
    pub fn input(&self) -> &GoogleWorkerInput {
        &self.input
    }
    pub fn inspection_binding(&self) -> &str {
        &self.inspection_binding
    }
    pub fn detector_version(&self) -> &str {
        &self.detector_version
    }
}
