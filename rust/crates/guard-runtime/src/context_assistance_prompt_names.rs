//! The project's own names a prompt writes as code, which the code shown for
//! it has to hold.

use crate::context_assistance_engine::PickedExcerpt;
use crate::context_assistance_prompt_words::{spellings, term_form};

/// The names the prompt writes as code that some project file holds, such as
/// `parse_filter_block` of `Parser.parse_filter_block`, lowercase with `_`
/// and `-` dropped. `spelled` counts the files holding each of `terms`. The
/// class a dotted name is read on is left out, since a file can use a class
/// without holding the member asked about. A name no file holds, such as a
/// helper the prompt asks to add, gives nothing.
pub(super) fn held_names(prompt: &str, terms: &[String], spelled: &[usize]) -> Vec<String> {
    let written = spellings(prompt);
    let qualifiers: Vec<String> = (written.iter())
        .filter_map(|name| name.rsplit_once('.'))
        .flat_map(|(qualifier, _)| qualifier.split('.'))
        .map(joined)
        .collect();
    let mut names: Vec<String> = Vec::new();
    for name in &written {
        let name = joined(name.rsplit('.').next().unwrap_or(name));
        let at = terms.iter().position(|term| *term == term_form(&name));
        let held = at.is_some_and(|at| spelled.get(at).is_some_and(|&n| n > 0));
        if held && !qualifiers.contains(&name) && !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// `picked`, or nothing when the prompt names project code and no excerpt
/// holds any of it: code that only shares the prompt's other words is about
/// something else, and the matched files serve better.
pub(super) fn holding<'a>(picked: &'a [PickedExcerpt], names: &[String]) -> &'a [PickedExcerpt] {
    let holds = |excerpt: &PickedExcerpt| {
        let text = joined(&excerpt.text);
        names.iter().any(|name| text.contains(name.as_str()))
    };
    if names.is_empty() || picked.iter().any(holds) {
        picked
    } else {
        &[]
    }
}

fn joined(word: &str) -> String {
    word.replace(['_', '-'], "").to_lowercase()
}

#[cfg(test)]
#[path = "context_assistance_prompt_names_tests.rs"]
mod tests;
