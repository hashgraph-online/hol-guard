//! The credential-word signal for a call that names only tracked documents.
//!
//! `perl -pi -e 's/v1/v2/' contributions/command.kubernetes-secrets.json` and
//! a structured Read of the same file raise the signal through the word in
//! the file name alone. When every path value and every command word that
//! carries such a word resolves to a document proven by
//! `tracked_credential_names`, the signal is cleared; the rest of the command
//! text must then hold no credential word of its own.

use super::GenericSignals;
use crate::pretool::search_scope_tracked::names::{
    self, command_words, moves_directory, resolves_to_tracked, without_tracked_words,
};
use crate::pretool::secret_aliases::decision_names_secret_alias;
use crate::pretool::{sensitive_command, sensitive_command_input, PathContext, PreToolDecisionV1};
use serde_json::Value;

impl GenericSignals {
    /// Clears the credential-word signal for a call that names only tracked
    /// documents, then adds any operand that reaches a secret through a link.
    pub(in crate::pretool::generic) fn settle_tracked_names(
        &mut self,
        decision: Option<&Result<PreToolDecisionV1, String>>,
        context: PathContext<'_>,
    ) {
        if self.sensitive_target
            && !self.non_path_sensitive_target
            && !self.declares_secret_object
            && self.names_only_tracked_documents(decision, context.cwd)
        {
            self.sensitive_target = false;
            self.independent_sensitive_target = false;
        }
        // A link to a secret file is that secret under another name.
        self.sensitive_target |= decision_names_secret_alias(decision, context);
    }

    fn names_only_tracked_documents(
        &self,
        decision: Option<&Result<PreToolDecisionV1, String>>,
        cwd: Option<&str>,
    ) -> bool {
        let paths_proven = self
            .path_values
            .iter()
            .filter(|value| sensitive_command(value))
            .all(|value| resolves_to_tracked(value, cwd));
        let Some(command) = self.command.as_deref() else {
            return paths_proven;
        };
        let Some(Ok(decision)) = decision else {
            return false;
        };
        let model = &decision.command_model;
        // Redirect targets, assignments and any text the model did not split
        // into words stay in the rest and keep the signal.
        paths_proven && {
            let moves = moves_directory(model);
            let refs = crate::pretool::ref_name_words::ref_names(model, cwd, moves);
            without_tracked_words(command, command_words(model), cwd, moves, &refs)
                .is_some_and(|rest| !sensitive_command_input(&rest))
        }
    }
}

/// The new-text keys of the substring edits hosts send.
const EDIT_TEXT_KEYS: [&str; 4] = ["new_string", "newString", "newText", "new_str"];

/// Escapes that spell a letter in JSON, YAML or TOML strings, and the YAML
/// line continuation that joins two halves of a word.
const LETTER_ESCAPES: [&str; 5] = ["\\u", "\\U", "\\x", "\\\n", "\\\r"];

/// Whether a string anywhere in `payload` declares a Kubernetes `Secret`, or
/// a substring edit or whole-file body in it may. An edit or write that turns
/// a tracked document into a `Secret` manifest keeps the signal, though the
/// file on disk still proves clean.
pub(super) fn declares_secret_object(payload: &Value) -> bool {
    match payload {
        Value::String(text) => names::declares_secret_object(text),
        Value::Array(items) => items.iter().any(declares_secret_object),
        Value::Object(map) => {
            edit_names_secret(map)
                || writes_unproven_body(map)
                || map.values().any(declares_secret_object)
        }
        _ => false,
    }
}

/// Whether an edit's new text names `secret` or holds an escape that can
/// spell it or `kind`, as a command naming a credential word beside a
/// tracked path keeps its review. `old_string: ConfigMap` with
/// `new_string: Secret` names no `kind` in either string, and
/// `"\u006bind": "\u0053ecret"` names neither word plainly. The old text is
/// not consulted: it can hold the same words, so a count would let the
/// replacement through. A unified diff needs no such check: it replaces
/// whole lines, so the `kind` key travels with its value.
fn edit_names_secret(map: &serde_json::Map<String, Value>) -> bool {
    EDIT_TEXT_KEYS.iter().any(|key| {
        map.get(*key).and_then(Value::as_str).is_some_and(|text| {
            text.to_ascii_lowercase().contains("secret")
                || LETTER_ESCAPES.iter().any(|escape| text.contains(escape))
        })
    })
}

/// Whether a whole-file body would fail the proof the file on disk is held
/// to once written: a `Secret` kind, or an escape outside decoded JSON.
fn writes_unproven_body(map: &serde_json::Map<String, Value>) -> bool {
    ["content", "contents"].iter().any(|key| {
        map.get(*key)
            .and_then(Value::as_str)
            .is_some_and(names::secret_object)
    })
}
