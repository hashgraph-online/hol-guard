//! The script a bounded inline shell runs, as the contained sink plans it.
//!
//! The review reads `bash -ec 'pytest -q'` as `pytest -q`, so a sink that
//! plans the call again has to plan that script or it refuses the run the
//! review sent it. Only a script that is one plain command is read through:
//! the sink runs a projected script without the shell's own flags, and `-e`
//! is what stops `pytest -q; echo done` from reporting success after pytest
//! fails.

use crate::CommandModelRequestV1;

/// The one command a bounded inline shell runs, or `None` for any other text.
pub(crate) fn inline_shell_target(text: &str) -> Option<String> {
    let request = CommandModelRequestV1 {
        command: text.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "contained-target".into(),
    };
    let model = crate::parse_inline_shell_script(&request, text.trim())?;
    if model.segments.len() != 1 {
        return None;
    }
    crate::command_parse_surface::inline_shell_script_text(&request)
}
