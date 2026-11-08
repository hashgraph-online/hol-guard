//! Which definitions the map shows: those the prompt names, the functions
//! left to be written in a file it names, and the types they build on.
use super::{more, rename, term_form, written_name, Asked, File, Kind};

const MAX_NAMED_DEFINITIONS: usize = 6;
/// Functions left to be written that stand in for a named file's outline.
const MAX_STUBS: usize = 2;

pub(super) struct Pick {
    pub(super) file: usize,
    pub(super) at: usize,
    pub(super) base: bool,
    /// Named by the prompt, so it may be shown whole.
    pub(super) whole: bool,
}

/// The top-level definition of each name the prompt gives, in the prompt's
/// order: in source, not tests, and in the file defining the most of the
/// prompt's names when several do. A name written as code that no top-level
/// definition holds is a member, such as a method, found the same way, and
/// so is one the prompt writes after its class (`peekable.prepend`). Then
/// the types they build on that the same file defines, which the change
/// usually has to follow.
pub(super) fn named_definitions(
    files: &[File],
    names: &[(&str, bool)],
    asked: &Asked,
) -> Vec<Pick> {
    // `cachedmethod` is the function the prompt writes, not the
    // `CachedMethod` class beside it.
    let spelled = |file: &File, at: usize| {
        written_name(file.opening(at)).is_some_and(|word| asked.spellings.contains(&word))
    };
    let top = |file: &File, name: &str| {
        let mut found = (0..file.sections.len()).filter(|&at| {
            file.parent[at].is_none() && file.sections[at].name.as_deref() == Some(name)
        });
        let first = found.next()?;
        if spelled(file, first) {
            return Some(first);
        }
        Some(found.find(|&at| spelled(file, at)).unwrap_or(first))
    };
    let defining = |file: &File| {
        names
            .iter()
            .filter(|(name, _)| top(file, name).is_some())
            .count()
    };
    // A file the prompt names holds the definition it means, even one named
    // like a test file (`src/jinja2/tests.py`).
    let in_named = |file: &File| more::named_in(file.path, &asked.named);
    // Sample code holds a word the prompt only mentions in passing, but not
    // a name it writes as code.
    let best = |name: &str, member: bool, shaped: bool| {
        (files.iter().enumerate())
            .filter(|(_, file)| file.kind == Kind::Source || in_named(file))
            .filter(|(_, file)| shaped || !more::sample(file.path))
            .filter_map(|(index, file)| {
                let at = if member {
                    more::member(file, name, names)
                } else {
                    top(file, name)
                };
                at.map(|at| (index, at))
            })
            .max_by(|(a, _), (b, _)| {
                let (a, b) = (&files[*a], &files[*b]);
                (in_named(a).cmp(&in_named(b)))
                    .then(defining(a).cmp(&defining(b)))
                    .then(
                        b.path
                            .matches('/')
                            .count()
                            .cmp(&a.path.matches('/').count()),
                    )
                    .then(b.path.cmp(a.path))
            })
    };
    // `peekable.prepend` is that method, not a `prepend` function elsewhere.
    let dotted = |name: &str| {
        (files.iter().enumerate())
            .filter(|(_, file)| file.kind == Kind::Source)
            .find_map(|(index, file)| {
                (0..file.sections.len())
                    .find(|&at| {
                        file.parent[at].is_some()
                            && file.sections[at].name.as_deref() == Some(name)
                            && asked.spellings.contains(&file.qualified(at))
                    })
                    .map(|at| (index, at))
            })
    };
    let mut picks: Vec<Pick> = Vec::new();
    for &(name, shaped) in names {
        let found = (shaped.then(|| dotted(name)).flatten())
            .or_else(|| best(name, false, shaped))
            .or_else(|| shaped.then(|| best(name, true, shaped)).flatten());
        if let Some((file, at)) = found {
            if !picks.iter().any(|pick| pick.file == file && pick.at == at) {
                picks.push(Pick {
                    file,
                    at,
                    base: false,
                    whole: true,
                });
            }
        }
    }
    if picks.is_empty() {
        for (file, item) in files.iter().enumerate().filter(|(_, item)| in_named(item)) {
            // A function left to be written is the one a prompt naming only
            // its file means: "last is not implemented (more.py)".
            let pick = |at, whole| Pick {
                file,
                at,
                base: false,
                whole,
            };
            let stubs: Vec<usize> = (0..item.sections.len())
                .filter(|&at| !item.container(at) && rename::stubbed(item, at))
                .take(MAX_STUBS)
                .collect();
            if stubs.is_empty() {
                picks.extend(more::outline(item).map(|at| pick(at, false)));
            }
            picks.extend(stubs.into_iter().map(|at| pick(at, true)));
        }
    }
    let mut bases = Vec::new();
    for pick in picks
        .iter()
        .filter(|pick| files[pick.file].container(pick.at))
    {
        let file = &files[pick.file];
        let opening = file.opening(pick.at);
        let words = opening.split(|c: char| !(c.is_alphanumeric() || c == '_'));
        for word in words.skip(2).filter(|word| !word.is_empty()) {
            let Some(at) = top(file, &term_form(word)) else {
                continue;
            };
            let taken = |p: &Pick| p.file == pick.file && p.at == at;
            if at != pick.at && !picks.iter().any(taken) && !bases.iter().any(taken) {
                bases.push(Pick {
                    file: pick.file,
                    at,
                    base: true,
                    whole: false,
                });
            }
        }
    }
    picks.extend(bases);
    picks.truncate(MAX_NAMED_DEFINITIONS);
    picks
}
