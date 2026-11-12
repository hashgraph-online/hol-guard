//! What one preview may cost: the work of resolving it and the bytes of its
//! reply. A request over either is refused with a stable code, never cut, so
//! a preview that is reviewed and approved is always the complete one.

use guard_command::extension_control::MAX_CONTROL_LAYERS;
use guard_contracts::{ExtensionControlPreviewChangedTargetV1, NativeExtensionControlLayerV1};

use crate::extension_control_op::{REPLY_TOO_LARGE, TOO_MANY_ITEMS};

use super::catalog::PreviewCatalog;

/// Most comparisons one preview makes. Each resolution (the current layers,
/// the proposed layers and one per changed target) compares every catalog
/// permission's closure and every control against the layers. A real catalog
/// and mutation are orders of magnitude below it.
const MAX_PREVIEW_WORK: usize = 8_000_000;

/// The reply a preview may fill: the transport's reply cap less room for the
/// envelope the preview travels in.
pub(super) const MAX_PREVIEW_REPLY_BYTES: usize = crate::MAX_NATIVE_RESPONSE_BYTES - 64 * 1024;

/// The controls of the layers a resolution reads.
fn control_count(layers: &[NativeExtensionControlLayerV1]) -> usize {
    layers
        .iter()
        .take(MAX_CONTROL_LAYERS + 1)
        .map(|layer| layer.controls.len())
        .sum()
}

/// How many closure entries the catalog's permissions and the changed
/// extensions may hold in all, so that `resolutions` resolutions stay within
/// the work bound.
pub(super) fn closure_budget(
    catalog: &PreviewCatalog<'_>,
    current_layers: &[NativeExtensionControlLayerV1],
    proposed_layers: &[NativeExtensionControlLayerV1],
    resolutions: usize,
) -> Result<usize, String> {
    let per_resolution = MAX_PREVIEW_WORK / resolutions.max(1);
    let fixed = catalog
        .registry
        .permissions
        .len()
        .saturating_add(control_count(current_layers).max(control_count(proposed_layers)));
    per_resolution
        .checked_sub(fixed)
        .ok_or_else(|| TOO_MANY_ITEMS.to_owned())
}

/// The bytes the changed targets so far will take in the reply.
#[derive(Default)]
pub(super) struct ReplyBudget {
    bytes: usize,
}

impl ReplyBudget {
    /// Counts one more changed target, refusing once the reply would not fit.
    pub(super) fn admit(
        &mut self,
        target: &ExtensionControlPreviewChangedTargetV1,
    ) -> Result<(), String> {
        let encoded =
            serde_json::to_vec(target).map_err(|_| "native_response_encode_failed".to_owned())?;
        // One byte for the comma between targets.
        self.bytes = self.bytes.saturating_add(encoded.len()).saturating_add(1);
        if self.bytes > MAX_PREVIEW_REPLY_BYTES {
            return Err(REPLY_TOO_LARGE.to_owned());
        }
        Ok(())
    }
}
