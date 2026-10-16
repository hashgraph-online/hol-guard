//! Command operands that reach a secret file through a symbolic link.
//!
//! The text screens recognize a secret by how a command spells its path
//! (`cat .env`). A link such as `notes.txt -> .env` reaches the same file
//! under an ordinary name, so each literal operand is also resolved on disk
//! and classified by the file it reaches. Operands already spelled as a secret
//! path stay with those screens; this only adds the reach through a link, so
//! a link never makes a read of a secret look more ordinary than a direct one.
use super::{PathContext, PreToolDecisionV1};
use crate::shell_secret_read_support::{classify_secret_path, sensitive_path};
use crate::CanonicalCommandV1;
use std::path::Path;

/// Whether any literal operand of `model` resolves, through a symbolic link
/// below the working or home directory, to a secret-classified file.
pub(super) fn names_secret_alias(model: &CanonicalCommandV1, context: PathContext<'_>) -> bool {
    let cwd = context.cwd.map(Path::new);
    let home = context.home_dir.map(Path::new);
    model
        .segments
        .iter()
        .flat_map(|segment| segment.arguments.iter())
        .map(String::as_str)
        .filter_map(operand)
        .any(|operand| {
            classify_secret_path(operand, cwd, home).is_none()
                && sensitive_path(operand, cwd, home).is_some()
        })
}

/// `names_secret_alias` for a command decision the authority did not prove
/// benign. A proven-benign decision already settled what its operands reach.
pub(super) fn decision_names_secret_alias(
    decision: Option<&Result<PreToolDecisionV1, String>>,
    context: PathContext<'_>,
) -> bool {
    decision
        .and_then(|decision| decision.as_ref().ok())
        .is_some_and(|decision| {
            !decision.explicitly_benign && names_secret_alias(&decision.command_model, context)
        })
}

/// The path a literal argument names: a plain word, or the value of a long
/// `--option=value`. Other options name no file.
fn operand(argument: &str) -> Option<&str> {
    let value = match argument.strip_prefix("--") {
        Some(option) => option.split_once('=')?.1,
        None if argument.starts_with('-') => return None,
        None => argument,
    };
    (!value.is_empty() && !value.contains('\0')).then_some(value)
}

#[cfg(test)]
#[path = "secret_aliases_tests.rs"]
mod tests;
