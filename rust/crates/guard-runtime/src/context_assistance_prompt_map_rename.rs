//! For a rename, every line naming the old name in the files read, with its
//! text, and whether those files are all the project files that hold it, so
//! the agent need not search or open them again before editing. For a stubbed-out
//! function, the other lines naming it, with their text: the module state,
//! imports and platform versions its body has to use.
use super::{Asked, File, Kind, Pick, Sought, Span, CHECK_EVERY};
use crate::context_assistance_prompt_words::term_form;
use std::time::Instant;

#[path = "context_assistance_prompt_map_rewrite.rs"]
mod rewrite;
use rewrite::Rewrite;

/// Names listed for one prompt: the old name, and at most one more.
const MAX_NAMES: usize = 2;
/// Lines listed with their text for a rename, and their length.
const MAX_RENAME_LINES: usize = 40;
const MAX_RENAME_CHARS: usize = 4_000;
/// Definitions calling a renamed one whose tests are looked for.
const MAX_CALLERS: usize = 3;
/// Lines listed with their text for a stub, and their length.
const MAX_STUB_LINES: usize = 24;
const MAX_STUB_CHARS: usize = 2_200;
/// How much of each line is listed, past its indentation, and how much of
/// the indentation.
const MAX_LINE_CHARS: usize = 160;
const MAX_INDENT_CHARS: usize = 48;
/// What a body left to be written holds.
pub(in super::super) const STUB_MARKS: [&str; 4] = [
    "NotImplementedError",
    "todo!(",
    "unimplemented!(",
    "not implemented",
];

/// For a rename, a block per name the prompt writes as code that a file
/// read holds: its title, and per file the lines naming it, with the one
/// command making the rename when a single name is renamed. Empty for any
/// other prompt, or once `until` passes.
pub(super) fn blocks(
    files: &[File],
    sought: &[Sought],
    asked: &Asked,
    until: Instant,
) -> (Blocks, Option<Rewrite>) {
    if !asked.everywhere {
        return (Vec::new(), None);
    }
    let found: Vec<_> = (sought.iter())
        .filter(|item| item.name && !item.phrase && !owner_only(&asked.spellings, &item.text))
        .filter_map(|item| {
            // `_batched` is renamed, not `batched` beside it: the lines
            // naming it as the prompt spells it, when any file does.
            let spelled = (asked.spellings.iter()).find(|word| term_form(word) == item.text);
            let found = spelled.and_then(|word| {
                let new = renamed_to(&asked.renames, word);
                every_line(files, item, Some(word.as_str()), new, until)
            });
            found.or_else(|| every_line(files, item, None, None, until))
        })
        .take(MAX_NAMES)
        .collect();
    let rewrite = match &found[..] {
        [(_, rewrite)] if asked.renames.len() == 1 => rewrite.clone(),
        _ => None,
    };
    (
        found.into_iter().flat_map(|(blocks, _)| blocks).collect(),
        rewrite,
    )
}

/// Titled blocks of lines.
type Blocks = Vec<(String, Vec<String>)>;

/// The name the prompt renames `old` to: "rename `a` to `b`".
fn renamed_to<'a>(renames: &'a [(String, String)], old: &str) -> Option<&'a str> {
    (renames.iter().find(|(from, _)| from == old))
        .map(|(_, to)| to.as_str())
        .filter(|word| (word.chars()).all(|c| c.is_alphanumeric() || c == '_'))
}

/// Whether the prompt writes `term` only before a dot, as `peekable` in
/// `peekable.prepend`, where the member is renamed and not its class.
fn owner_only(spellings: &[String], term: &str) -> bool {
    let owner = |word: &&String| {
        (word.rsplit_once('.'))
            .is_some_and(|(owner, _)| term_form(owner.rsplit('.').next().unwrap_or(owner)) == term)
    };
    let dotted = spellings.iter().filter(owner).count();
    dotted > 0
        && spellings
            .iter()
            .filter(|word| term_form(word) == term)
            .count()
            <= dotted
}

/// Where one file holds a name.
#[derive(Default)]
struct Naming {
    /// Some line holds the name with `_` and `-` dropped.
    held: bool,
    /// The lines naming it whole.
    lines: Vec<usize>,
    /// The other lines naming a longer name holding it, such as
    /// `_get_default_module_async` for `_get_default_module`.
    longer: Vec<usize>,
    /// The lines building a longer name from it, and the longer names
    /// starting with it, which such a line may build.
    building: Vec<usize>,
    extended: Vec<String>,
    /// Its first spelling written.
    written: Option<String>,
}

/// Where `file` holds `term`, or `exact` where given; `None` once `until`
/// passes.
fn naming(file: &File, term: &str, exact: Option<&str>, until: Instant) -> Option<Naming> {
    let mut found = Naming::default();
    for (number, line) in file.lines.iter().enumerate() {
        if number % CHECK_EVERY == 0 && Instant::now() >= until {
            return None;
        }
        if !line.to_lowercase().replace(['_', '-'], "").contains(term) {
            continue;
        }
        found.held = true;
        let words = line
            .split(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '-')))
            .filter(|word| !word.is_empty());
        let named =
            |word: &&str| exact.map_or_else(|| term_form(word) == term, |exact| *word == exact);
        let longer = |word: &str| exact.is_some_and(|exact| joined(word, exact));
        if let Some(word) = words.clone().find(named) {
            if found.written.is_none() {
                found.written = Some(word.to_owned());
            }
            found.lines.push(number + 1);
            if builds_on(line, word) {
                found.building.push(number + 1);
            }
        } else if words.clone().any(longer) {
            found.longer.push(number + 1);
            let extended = |word: &&str| exact.is_some_and(|exact| word.starts_with(exact));
            for word in words.filter(extended) {
                if !found.extended.iter().any(|known| known == word) {
                    found.extended.push(word.to_owned());
                }
            }
        }
    }
    Some(found)
}

/// Whether `word` is a longer name joining `name` with other words:
/// `_get_default_module_async` or `test_get_default_module`, not `chunked`.
fn joined(word: &str, name: &str) -> bool {
    let edge = |c: Option<char>, end: Option<char>| {
        c.is_none_or(|c| matches!(c, '_' | '-')) || end.is_some_and(|c| matches!(c, '_' | '-'))
    };
    word != name
        && (word.match_indices(name)).any(|(at, _)| {
            let after = word[at + name.len()..].chars().next();
            edge(word[..at].chars().next_back(), name.chars().next())
                && (edge(after, name.chars().next_back()) || after.is_some_and(char::is_uppercase))
        })
}

/// Whether `line` writes `name` in a string as the start of a name it
/// builds: `f"_get_default_module{suffix}"`, `` `${name}${suffix}` ``,
/// `"name%s" % suffix` or `"name" + suffix`.
fn builds_on(line: &str, name: &str) -> bool {
    let quote = |c: char| matches!(c, '"' | '\'' | '`');
    (line.match_indices(name)).any(|(at, _)| {
        let rest = &line[at + name.len()..];
        let before = line[..at].chars().next_back();
        line[..at].contains(quote)
            && !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
            && (rest.starts_with(['{', '%'])
                || rest.starts_with("${")
                || (rest.strip_prefix(quote))
                    .is_some_and(|rest| rest.trim_start().starts_with('+')))
    })
}

/// The files read that hold `item` with `_` and `-` dropped, as the walk
/// counted them, and each line naming it whole, with its text, so the edit
/// can be written without opening them; then the lines naming a longer name
/// holding it, which a search for it finds too. The list says it is
/// complete only when the walk read every project file, found no file
/// holding it beyond these, and every line fits.
fn every_line(
    files: &[File],
    item: &Sought,
    exact: Option<&str>,
    new: Option<&str>,
    until: Instant,
) -> Option<(Blocks, Option<Rewrite>)> {
    let mut written = None;
    let mut holding = 0;
    let mut entries = Vec::new();
    let mut longer = Vec::new();
    let mut length = 0;
    let mut whole = true;
    let mut fits = |entry: String, entries: &mut Vec<String>, count: usize| {
        let fit = count < MAX_RENAME_LINES && length + entry.len() <= MAX_RENAME_CHARS;
        if fit {
            length += entry.len();
            entries.push(entry);
        }
        fit
    };
    let mut others = Vec::new();
    let mut building = Vec::new();
    let mut extended: Vec<String> = Vec::new();
    let mut holders: Vec<&File> = Vec::new();
    for file in files {
        let found = naming(file, &item.text, exact, until)?;
        written = written.or(found.written);
        holding += usize::from(found.held);
        if !found.lines.is_empty() {
            holders.push(file);
        }
        for number in found.lines {
            let count = entries.len();
            whole &= fits(line_entry(file, number), &mut entries, count);
        }
        others.extend(found.longer.into_iter().map(|number| (file, number)));
        building.extend(
            found
                .building
                .into_iter()
                .map(|number| line_entry(file, number)),
        );
        for word in found.extended {
            if !extended.contains(&word) {
                extended.push(word);
            }
        }
    }
    for (file, number) in others {
        let count = entries.len() + longer.len();
        whole &= fits(line_entry(file, number), &mut longer, count);
    }
    let name = written?;
    whole &= item.spelled == Some(holding);
    let title = if whole {
        format!("Every line naming `{name}`; no other project file holds it:")
    } else {
        format!("Lines naming `{name}` in the files read; other files may hold it too:")
    };
    // Only for a list that is whole and builds no longer name, which one
    // replacement would break.
    let rewrite = if whole && building.is_empty() {
        exact.zip(new)
    } else {
        None
    };
    let rewrite = rewrite.and_then(|(old, new)| Rewrite::new(old, new, &holders));
    let mut blocks = vec![(title, entries)];
    // `f"_get_default_module{choose_async('_async')}"` also calls
    // `_get_default_module_async`, which renaming only the first breaks.
    if !building.is_empty() {
        let such = (extended.iter().take(MAX_NAMES))
            .map(|word| format!("`{word}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let such = if such.is_empty() {
            String::new()
        } else {
            format!(", such as {such}")
        };
        // Spelled out, since an agent told only to keep the names defined
        // still wrote `_get_default_module_impl{...}`.
        // The ending comes from a longer name whose ending a building line
        // writes, not from any longer name a file holds.
        let suffix = (extended.iter())
            .filter_map(|longer| longer.strip_prefix(name.as_str()))
            .find(|end| !end.is_empty() && building.iter().any(|line| line.contains(end)));
        let instead = match (new, suffix) {
            (Some(new), Some(suffix)) => format!(
                "; with `{new}` written in place of `{name}`, they would build `{new}{suffix}` instead"
            ),
            _ => String::new(),
        };
        blocks.push((
            format!(
                "These lines build a longer name from `{name}`{such}{instead}. Every name they build must still be defined after the rename:"
            ),
            building,
        ));
    }
    if !longer.is_empty() {
        blocks.push((
            format!("Lines naming a longer name holding `{name}`:"),
            longer,
        ));
    }
    Some((blocks, rewrite))
}

/// For a rename of a definition no test names, the source definitions
/// naming it, whose tests check it instead: `_complex_sumprod` is tested
/// through `dft` and `idft`. Empty once `until` passes.
pub(super) fn callers(files: &[File], chosen: &[Pick], until: Instant) -> Vec<String> {
    let Some(pick) = chosen.iter().find(|pick| !pick.base) else {
        return Vec::new();
    };
    let Some(name) = files[pick.file].sections[pick.at].name.as_deref() else {
        return Vec::new();
    };
    let tested = (files.iter().filter(|file| file.kind == Kind::Test))
        .any(|file| naming(file, name, None, until).is_none_or(|found| !found.lines.is_empty()));
    let mut found: Vec<String> = Vec::new();
    for file in files
        .iter()
        .filter(|file| file.kind == Kind::Source && !tested)
    {
        let Some(hits) = naming(file, name, None, until) else {
            return Vec::new();
        };
        for number in hits.lines {
            let holder = (0..file.sections.len())
                .filter(|&at| !file.container(at))
                .filter(|&at| (file.sections[at].start..=file.sections[at].end).contains(&number))
                .max_by_key(|&at| file.sections[at].start);
            let caller = holder.and_then(|at| file.sections[at].name.clone());
            if let Some(caller) = caller.filter(|caller| caller != name && !found.contains(caller))
            {
                found.push(caller);
            }
            if found.len() == MAX_CALLERS {
                return found;
            }
        }
    }
    found
}

/// Line `number` of `file` as a search prints it: path, number and text,
/// indented as the file indents it. Without the indentation an agent
/// searched again before its edit, to write the new lines at the right depth.
fn line_entry(file: &File, number: usize) -> String {
    let line = file.lines[number - 1].trim_end();
    let text = line.trim_start();
    let indent: String = (line[..line.len() - text.len()].chars())
        .take(MAX_INDENT_CHARS)
        .collect();
    let text: String = text.chars().take(MAX_LINE_CHARS).collect();
    format!("{}:{number}:{indent}{text}", file.path)
}

/// Whether section `at` of `file` is a body left to be written.
pub(super) fn stubbed(file: &File, at: usize) -> bool {
    let section = &file.sections[at];
    let body = (file.lines)
        .get(section.start - 1..section.end.min(file.lines.len()))
        .unwrap_or_default();
    (body.iter()).any(|line| STUB_MARKS.iter().any(|mark| line.contains(mark)))
}

/// For the first chosen definition whose body is left to be written, the
/// other lines in the files read naming it, with their text, leaving out
/// the code the map already shows.
pub(super) fn stub(
    files: &[File],
    chosen: &[Pick],
    shown: &[Span],
    until: Instant,
) -> Option<(String, Vec<String>)> {
    let (file, section) = chosen.iter().find_map(|pick| {
        let file = &files[pick.file];
        (pick.whole && stubbed(file, pick.at)).then_some((file, &file.sections[pick.at]))
    })?;
    let name = section.name.as_deref()?;
    // Spelled as its definition writes it.
    let opening = file
        .lines
        .get(section.start - 1)
        .copied()
        .unwrap_or_default();
    let written = (opening.split(|c: char| !(c.is_alphanumeric() || c == '_')))
        .find(|word| term_form(word) == name)
        .map(str::to_owned);
    let inside = |path: &str, number: usize| {
        (path == file.path && (section.start..=section.end).contains(&number))
            || (shown.iter())
                .any(|span| span.path == path && (span.start..=span.end).contains(&(number as u64)))
    };
    let mut entries = Vec::new();
    let mut length = 0;
    let mut whole = true;
    'files: for other in files {
        let found = naming(other, name, None, until)?;
        for number in found.lines.into_iter().filter(|&n| !inside(other.path, n)) {
            let entry = line_entry(other, number);
            if entries.len() == MAX_STUB_LINES || length + entry.len() > MAX_STUB_CHARS {
                whole = false;
                break 'files;
            }
            length += entry.len();
            entries.push(entry);
        }
    }
    if entries.is_empty() {
        return None;
    }
    let name = written.as_deref().unwrap_or(name);
    let title = if whole {
        format!("Other lines naming `{name}` in the files read:")
    } else {
        format!("First other lines naming `{name}` in the files read:")
    };
    Some((title, entries))
}
