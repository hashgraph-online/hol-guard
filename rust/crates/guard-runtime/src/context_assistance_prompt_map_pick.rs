//! Which definitions the map shows: those the prompt names, the functions
//! left to be written in a file it names, and the types they build on.
use super::{more, rename, term_form, written_name, Asked, File, Kind};

const MAX_NAMED_DEFINITIONS: usize = 6;
/// Functions left to be written that stand in for a named file's outline.
const MAX_STUBS: usize = 2;
/// Definitions shown beside a function left to be written.
const MAX_HELPERS: usize = 3;
/// Section names, as `term_form` gives them, of a class's constructor.
const CONSTRUCTORS: [&str; 3] = ["init", "constructor", "new"];

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
    let helping = picks
        .iter()
        .find(|pick| {
            let file = &files[pick.file];
            pick.whole && !file.container(pick.at) && rename::stubbed(file, pick.at)
        })
        .map(|stub| helpers(files, stub, |name| best(name, false, true)))
        .unwrap_or_default();
    for (file, at) in helping {
        if !picks.iter().any(|pick| pick.file == file && pick.at == at) {
            picks.push(Pick {
                file,
                at,
                base: true,
                whole: true,
            });
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

/// What a function left to be written builds on: the constructor of the
/// class holding it, where the state it reads is set up (`ManyToMany.update`
/// needs `__init__`), and the definitions its docstring writes as code
/// (`zip_broadcast` raises ``UnequalIterablesError``), a method of the same
/// class first, then any found by `find`.
fn helpers(
    files: &[File],
    stub: &Pick,
    find: impl Fn(&str) -> Option<(usize, usize)>,
) -> Vec<(usize, usize)> {
    let file = &files[stub.file];
    let section = &file.sections[stub.at];
    let sibling = |name: &str| {
        let outer = file.parent[stub.at]?;
        (0..file.sections.len())
            .find(|&at| {
                at != stub.at
                    && file.parent[at] == Some(outer)
                    && file.sections[at].name.as_deref() == Some(name)
            })
            .map(|at| (stub.file, at))
    };
    let mut found: Vec<(usize, usize)> = CONSTRUCTORS
        .iter()
        .find_map(|&name| sibling(name))
        .into_iter()
        .collect();
    let body = (file.lines)
        .get(section.start - 1..section.end.min(file.lines.len()))
        .unwrap_or_default();
    for word in body.iter().flat_map(|line| written_as_code(line)) {
        let name = term_form(word);
        if found.len() == MAX_HELPERS || section.name.as_deref() == Some(name.as_str()) {
            continue;
        }
        let at = sibling(&name).or_else(|| find(&name));
        if let Some(at) = at.filter(|at| *at != (stub.file, stub.at) && !found.contains(at)) {
            found.push(at);
        }
    }
    found
}

/// The names `line` writes between backticks: `name`, ``name``,
/// :func:`name` or `module.name()`, by their last part.
fn written_as_code(line: &str) -> impl Iterator<Item = &str> {
    let parts: Vec<&str> = line.split('`').collect();
    let last = parts.len().saturating_sub(1);
    (parts.into_iter().enumerate())
        .filter(move |(index, _)| (1..last).contains(index))
        .map(|(_, part)| part.trim_end_matches("()"))
        .filter(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_alphanumeric() || matches!(c, '_' | '.'))
        })
        .filter_map(|part| part.rsplit('.').next())
        .filter(|name| {
            name.chars()
                .next()
                .is_some_and(|c| c.is_alphabetic() || c == '_')
        })
}
