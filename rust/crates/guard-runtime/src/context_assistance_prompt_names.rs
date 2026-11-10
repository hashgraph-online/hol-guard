//! The project's own names a prompt writes as code, which the code shown for
//! it has to hold.

use crate::context_assistance_prompt_words::{spellings, term_form};

/// The names the prompt writes as code, such as `parse_filter_block` of
/// `Parser.parse_filter_block`, lowercase with `_` and `-` dropped, each
/// beside its singular form, once some project file holds one of them.
/// `spelled` counts the files holding each of `terms`. The class a dotted
/// name is read on is left out, since a file can use a class without holding
/// the member asked about. The names go together, so code holding one a
/// search cut short did not reach still counts. Nothing when no file holds
/// any, as for a helper the prompt asks to add.
pub(super) fn held_names(prompt: &str, terms: &[String], spelled: &[usize]) -> Vec<String> {
    let written = spellings(prompt);
    let qualifiers: Vec<String> = (written.iter())
        .filter_map(|name| name.rsplit_once('.'))
        .flat_map(|(qualifier, _)| qualifier.split('.'))
        .map(joined)
        .collect();
    let mut names: Vec<String> = Vec::new();
    let mut held = false;
    for name in &written {
        let name = joined(name.rsplit('.').next().unwrap_or(name));
        if qualifiers.contains(&name) {
            continue;
        }
        let form = term_form(&name);
        let at = terms.iter().position(|term| *term == form);
        held = held || at.is_some_and(|at| spelled.get(at).is_some_and(|&n| n > 0));
        for name in [name, form] {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    if held {
        names
    } else {
        Vec::new()
    }
}

/// Whether `text` holds one of the `names`, written either way.
pub(super) fn holds(text: &str, names: &[String]) -> bool {
    let text = joined(text);
    names.iter().any(|name| text.contains(name.as_str()))
}

fn joined(word: &str) -> String {
    word.replace(['_', '-'], "").to_lowercase()
}

#[cfg(test)]
#[path = "context_assistance_prompt_names_tests.rs"]
mod tests;
