#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use crate::resident_state::{discover_states, token_from_state};

pub(crate) fn retire_state(
    scope: &Path,
    generation: u64,
    process_id: u32,
    process_start_marker: &str,
    expected_digest: &str,
    token: &[u8],
) {
    let Some(state) = discover_states(scope, expected_digest)
        .ok()
        .and_then(|states| {
            states
                .into_iter()
                .find(|state| state.generation == generation)
        })
    else {
        return;
    };
    if state.process_id != process_id || state.process_start_marker != process_start_marker {
        return;
    }
    let Ok(state_token) = token_from_state(&state) else {
        return;
    };
    if !crate::constant_time_eq(&state_token, token) {
        return;
    }
    let path = scope.join(format!("generation-{generation:020}.json"));
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return;
    };
    if metadata.is_file() && !metadata.file_type().is_symlink() {
        let _ = fs::remove_file(path);
    }
}
