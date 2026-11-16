//! `write_anchor`: `_write_and_verify_anchor`. The resident seals an anchor
//! only when the store has earned it, writes it into the credential vault and
//! reads it back. The caller mirrors the sealed text into the store it reads.
//!
//! An `anchored` anchor moves the vault onto the prepared row above the
//! committed head, and only while that row carries no authority of its own:
//! the vault still pins the head below it and the row authenticates as that
//! head's prepare. A `committed` anchor pins the committed snapshot the vault
//! already names. Nothing else is sealed.

use serde_json::{json, Value};

use super::records::{row_int, row_str, tampered, Anchor, Phase, Res};
use super::seals::anchor_json;
use super::Ctx;

const INVALID: &str = "invalid authority anchor";
const UNEARNED: &str = "extension control anchor not earned";

impl Ctx<'_> {
    pub(super) fn write_earned_anchor(&self) -> Res<Value> {
        let key = self.require_key()?;
        let (Some(revision), Some(snapshot_digest), Some(phase)) = (
            self.request.revision.filter(|revision| *revision >= 0),
            self.request
                .snapshot_digest
                .as_deref()
                .filter(|digest| digest.chars().count() == 64),
            self.request.phase.as_deref().and_then(Phase::parse),
        ) else {
            return Err(tampered(INVALID));
        };
        if !self.anchor_is_earned(revision, snapshot_digest, phase)? {
            return Err(tampered(UNEARNED));
        }
        let anchor = Anchor {
            revision,
            snapshot_digest: snapshot_digest.to_owned(),
            phase,
        };
        let sealed = anchor_json(&anchor, key)?;
        self.write_anchor(&sealed)?;
        // The export is best effort, as in `_export_last_good_authority`; the
        // caller warns when it failed.
        if anchor.phase == Phase::Committed && self.export_last_good(&anchor).is_err() {
            return Ok(json!({ "anchor_json": sealed, "last_good_exported": false }));
        }
        Ok(json!({ "anchor_json": sealed }))
    }

    fn anchor_is_earned(&self, revision: i64, snapshot_digest: &str, phase: Phase) -> Res<bool> {
        match phase {
            Phase::Prepared => Ok(false),
            Phase::Anchored => match self.pending_transition(revision)? {
                Some(row) => Ok(row_str(&row, "snapshot_digest")? == snapshot_digest
                    && self.pending_carries_no_authority(&row)?),
                None => Ok(false),
            },
            Phase::Committed => {
                let (Some(head), Some(current)) = (self.snapshot_row()?, self.anchor()?) else {
                    return Ok(false);
                };
                Ok(row_int(&head, "revision")? == revision
                    && row_str(&head, "snapshot_digest")? == snapshot_digest
                    && current.revision == revision
                    && current.snapshot_digest == snapshot_digest)
            }
        }
    }
}

#[cfg(test)]
#[path = "earned_anchor_tests.rs"]
mod tests;
