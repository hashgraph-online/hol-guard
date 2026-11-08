//! What else the file or class holding a function left to be written
//! defines. Writing the body again, an agent pages through the file for the
//! helpers it can call; the first line of each definition near the function,
//! with its lines, lets it open just the ones it needs.
use super::super::sections::members;
use super::rename::stubbed;
use super::{Asked, Entry, File, Pick, Span, MAX_LINE_CHARS};

/// The most of the list, and of one class's member list in it.
const MAX_BESIDE_CHARS: usize = 1_400;
const MAX_CLASS_MEMBERS_CHARS: usize = 240;

/// For the first chosen definition whose body is left to be written, the
/// definitions beside it: the other members of its class, or the file's
/// other top-level definitions, nearest first, each as its lines and first
/// line, a class with its members. Not shown again when an earlier prompt of
/// the session was shown the same list.
pub(super) fn beside(files: &[File], chosen: &[Pick], asked: &Asked) -> Option<(String, Entry)> {
    let (file, at) = chosen.iter().find_map(|pick| {
        let file = &files[pick.file];
        (pick.whole && stubbed(file, pick.at)).then_some((file, pick.at))
    })?;
    let outer = file.parent[at];
    let start = file.sections[at].start;
    let mut near: Vec<usize> = (0..file.sections.len())
        .filter(|&other| other != at && file.parent[other] == outer)
        .filter(|&other| file.sections[other].name.is_some())
        .collect();
    near.sort_by_key(|&other| file.sections[other].start.abs_diff(start));
    let mut kept: Vec<(usize, usize, String)> = Vec::new();
    let mut length = 0;
    for other in near {
        let line = line(file, other);
        if length + line.len() + 1 > MAX_BESIDE_CHARS {
            break;
        }
        length += line.len() + 1;
        let section = &file.sections[other];
        kept.push((section.start, section.end, line));
    }
    kept.sort_by_key(|(start, _, _)| *start);
    let first = kept.first()?.0;
    let last = kept.iter().map(|(_, end, _)| *end).max()?;
    let text = (kept.into_iter().map(|(_, _, line)| line))
        .collect::<Vec<_>>()
        .join("\n");
    let span = Span::new(file.path, first as u64, last as u64, &text);
    if asked.earlier.contains(&span) {
        return None;
    }
    let title = match outer {
        Some(outer) => format!(
            "Other members of {} in {}:",
            file.qualified(outer),
            file.path
        ),
        None => format!("Other definitions in {}:", file.path),
    };
    let entry = Entry {
        code: text.len(),
        text,
        shown: vec![span],
    };
    Some((title, entry))
}

/// `start-end` and the first line, then a class's members by name and lines.
fn line(file: &File, at: usize) -> String {
    let section = &file.sections[at];
    let first: String = file.opening(at).chars().take(MAX_LINE_CHARS).collect();
    let mut line = format!("{}-{} {first}", section.start, section.end);
    if !file.container(at) {
        return line;
    }
    let mut list = String::new();
    for (name, start, end) in members(&file.sections, &file.parent, &file.lines, at) {
        let piece = format!("{name} {start}-{end}");
        if list.len() + 2 + piece.len() > MAX_CLASS_MEMBERS_CHARS {
            list.push_str(", ...");
            break;
        }
        if !list.is_empty() {
            list.push_str(", ");
        }
        list.push_str(&piece);
    }
    if !list.is_empty() {
        line.push_str("\n  members: ");
        line.push_str(&list);
    }
    line
}
