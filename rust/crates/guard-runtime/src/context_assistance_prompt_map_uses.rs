//! Where in source the prompt's rarer words and quoted text are: the
//! functions holding them, with the lines they are on.
use super::super::sections::Section;
use super::{File, Kind, Sought, CHECK_EVERY};
use crate::context_assistance_engine::opened;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

const MAX_USES: usize = 8;
/// Line numbers shown for one function that holds the prompt's words.
const MAX_USE_LINES: usize = 3;

/// The functions in source that hold the prompt's rarer words in code, or
/// quoted text anywhere, each with the lines that hold them: those holding
/// quoted text first, then the most lines. A function needs two such lines
/// or quoted text. Also the words found, rarest first. `None` once `until`
/// passes.
pub(super) fn uses<'a>(
    files: &[File],
    rare: &[&'a Sought],
    until: Instant,
) -> Option<(Vec<&'a str>, Vec<String>)> {
    struct Use {
        file: usize,
        at: usize,
        lines: BTreeSet<usize>,
        words: BTreeSet<usize>,
        phrase: bool,
        named: bool,
    }
    let mut found: BTreeMap<(usize, usize), Use> = BTreeMap::new();
    for (index, file) in files.iter().enumerate() {
        if file.kind != Kind::Source || file.sections.is_empty() {
            continue;
        }
        let innermost = innermost(&file.sections, file.lines.len(), until)?;
        let mut closer: Option<&str> = None;
        for (number, line) in file.lines.iter().enumerate() {
            if number % CHECK_EVERY == 0 && Instant::now() >= until {
                return None;
            }
            // A word in a comment or docstring is prose about the code, so
            // only quoted text is looked for there.
            let comment = closer.is_some() || commented(line);
            closer = match closer {
                Some(mark) => (!line.contains(mark)).then_some(mark),
                None => opened(line),
            };
            let held: Vec<usize> = (holds(line, rare).into_iter())
                .filter(|&word| !comment || rare[word].phrase)
                .collect();
            let Some(at) = innermost[number] else {
                continue;
            };
            if held.is_empty() || file.container(at) {
                continue;
            }
            let entry = found.entry((index, at)).or_insert(Use {
                file: index,
                at,
                lines: BTreeSet::new(),
                words: BTreeSet::new(),
                phrase: false,
                named: false,
            });
            entry.lines.insert(number + 1);
            entry.phrase |= held.iter().any(|&word| rare[word].phrase);
            entry.named |= held.iter().any(|&word| rare[word].name);
            entry.words.extend(held);
        }
    }
    let mut kept: Vec<Use> = (found.into_values())
        // A name written as code is a lead on a single line too: a call to
        // `_import_common` is where a rename has to change it.
        .filter(|item| item.phrase || item.named || item.lines.len() >= 2)
        .collect();
    kept.sort_by(|a, b| {
        (b.phrase.cmp(&a.phrase))
            .then(b.lines.len().cmp(&a.lines.len()))
            .then(b.words.len().cmp(&a.words.len()))
    });
    kept.truncate(MAX_USES);
    let mut words: Vec<usize> = kept.iter().flat_map(|item| item.words.clone()).collect();
    words.sort_by(|a, b| rare[*b].rarity.total_cmp(&rare[*a].rarity).then(a.cmp(b)));
    words.dedup();
    let used = words
        .into_iter()
        .map(|word| rare[word].text.as_str())
        .collect();
    let listed = kept
        .iter()
        .map(|item| {
            let file = &files[item.file];
            let section = &file.sections[item.at];
            let lines: Vec<String> = (item.lines.iter().take(MAX_USE_LINES))
                .map(ToString::to_string)
                .collect();
            format!(
                "{}:{}-{} {} (lines {})",
                file.path,
                section.start,
                section.end,
                file.qualified(item.at),
                lines.join(", ")
            )
        })
        .collect();
    Some((used, listed))
}

/// A line that is a comment, or opens or wholly is a docstring. A Rust
/// attribute and a `*args` parameter are code.
fn commented(line: &str) -> bool {
    let code = line.trim_start();
    let attribute = code.starts_with("#[") || code.starts_with("#![");
    (code.starts_with('#') && !attribute)
        || code == "*"
        || ["//", "/*", "* ", "*/", "--", "\"\"\"", "'''"]
            .iter()
            .any(|mark| code.starts_with(mark))
}

/// Which of `sought` the line holds: a term as a whole word, spelled the way
/// `terms` spells it, or quoted text anywhere in it.
fn holds(line: &str, sought: &[&Sought]) -> Vec<usize> {
    let words = super::more::line_words(line);
    let lower = line.to_lowercase();
    (sought.iter().enumerate())
        .filter(|(_, item)| {
            if item.phrase {
                lower.contains(&item.text)
            } else {
                words.contains(&item.text)
            }
        })
        .map(|(index, _)| index)
        .collect()
}

/// For each of `count` lines, the index of the shortest section holding it,
/// the earliest of equal ones; `None` once `until` passes. Longer sections
/// are laid down first so shorter ones inside them overwrite their lines.
fn innermost(sections: &[Section], count: usize, until: Instant) -> Option<Vec<Option<usize>>> {
    let mut order: Vec<usize> = (0..sections.len()).collect();
    order.sort_by_key(|&at| {
        let section = &sections[at];
        (
            std::cmp::Reverse(section.end - section.start),
            std::cmp::Reverse(at),
        )
    });
    let mut innermost = vec![None; count];
    for (done, at) in order.into_iter().enumerate() {
        if done % CHECK_EVERY == 0 && Instant::now() >= until {
            return None;
        }
        let section = &sections[at];
        let lines = section.start.saturating_sub(1)..section.end.min(count);
        for line in innermost.get_mut(lines).unwrap_or_default() {
            *line = Some(at);
        }
    }
    Some(innermost)
}
