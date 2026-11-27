//! Special methods a prompt asks about by what they do. "Fix equality and
//! hashing of `numeric_range`" is a change to `numeric_range.__eq__` and
//! `__hash__`, though the prompt spells neither: those names hold no word of
//! it, so neither its names nor its rarer words place them.
use super::{written_name, File, Kind, Sought};

/// A word for what a special method does, as `term_form` gives it, and the
/// methods doing it, as `term_form` gives their names (`__reduce_ex__` is
/// `reduceex`).
const PROTOCOLS: &[(&str, &[&str])] = &[
    ("equality", &["eq", "ne"]),
    ("equal", &["eq", "ne"]),
    ("comparison", &["eq", "lt", "le", "gt", "ge"]),
    ("comparing", &["eq", "lt", "le", "gt", "ge"]),
    ("ordering", &["lt", "le", "gt", "ge"]),
    ("hash", &["hash"]),
    ("hashing", &["hash"]),
    ("hashable", &["hash"]),
    ("pickle", &["reduce", "reduceex", "getstate", "setstate", "getnewarg"]),
    ("pickling", &["reduce", "reduceex", "getstate", "setstate", "getnewarg"]),
    ("unpickling", &["setstate", "reduce", "reduceex", "getnewarg"]),
    ("copy", &["copy", "deepcopy"]),
    ("copying", &["copy", "deepcopy"]),
    ("deepcopy", &["deepcopy"]),
    ("repr", &["repr"]),
    ("length", &["len"]),
    ("iteration", &["iter", "next"]),
    ("membership", &["contain"]),
    ("truthiness", &["bool"]),
    ("indexing", &["getitem"]),
    ("slicing", &["getitem"]),
];
/// The most special methods one prompt adds.
const MAX_MEMBERS: usize = 4;

/// The special methods, by section name, of a class the prompt names that do
/// what its words ask about. A method only counts inside a named class, so
/// "equality" alone points nowhere.
pub(crate) fn members<'a>(
    files: &'a [File],
    sought: &[Sought],
    names: &[(&str, bool)],
) -> Vec<(&'a str, bool)> {
    let wanted: Vec<&str> = (sought.iter())
        .filter(|item| !item.phrase)
        .filter_map(|item| PROTOCOLS.iter().find(|(word, _)| *word == item.text))
        .flat_map(|(_, methods)| methods.iter().copied())
        .collect();
    let named = |name: Option<&str>| name.is_some_and(|name| names.iter().any(|(n, _)| *n == name));
    let mut found: Vec<(&'a str, bool)> = Vec::new();
    for file in files.iter().filter(|file| file.kind == Kind::Source) {
        for (at, section) in file.sections.iter().enumerate() {
            let Some(name) = section.name.as_deref() else {
                continue;
            };
            let outer = file.parent[at].and_then(|outer| file.sections[outer].name.as_deref());
            let special = written_name(file.opening(at))
                .is_some_and(|word| word.len() > 4 && word.starts_with("__") && word.ends_with("__"));
            if wanted.contains(&name)
                && special
                && named(outer)
                && !found.iter().any(|(had, _)| *had == name)
                && !names.iter().any(|(had, _)| *had == name)
            {
                found.push((name, true));
            }
        }
    }
    found.truncate(MAX_MEMBERS);
    found
}

#[cfg(test)]
#[path = "context_assistance_prompt_map_protocol_tests.rs"]
mod tests;
