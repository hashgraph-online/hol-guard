//! What else the file or class holding a function left to be written
//! defines. Writing the body again, an agent pages through the file for the
//! helpers it can call and for how its neighbors do the same kind of work;
//! the first line of each definition near the function, with its lines, and
//! the code of the nearest short ones save it that look.
use super::super::sections::members;
use super::more::{fenced, whole};
use super::rename::stubbed;
use super::{Asked, Entry, File, Pick, Span, MAX_LINE_CHARS};

/// The most of the list, and of one class's member list in it.
const MAX_BESIDE_CHARS: usize = 1_400;
const MAX_CLASS_MEMBERS_CHARS: usize = 240;
/// The most code shown under the nearest listed definitions.
const MAX_BESIDE_CODE_CHARS: usize = 1_800;

/// For the first chosen definition whose body is left to be written, the
/// definitions beside it: the other members of its class, or the file's
/// other top-level definitions. The nearest ones that fit are kept and listed
/// in file order, each as its lines and first line, a class with its members.
/// The nearest short functions also come with their code, unless the map or
/// an earlier prompt already shows it. Not shown again when an earlier prompt
/// of the session was shown the same list.
pub(super) fn beside(
    files: &[File],
    chosen: &[Pick],
    asked: &Asked,
    shown: &[Span],
) -> Option<(String, Entry)> {
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
    let mut room = MAX_BESIDE_CODE_CHARS;
    for other in near {
        let mut line = line(file, other);
        if length + line.len() + 1 > MAX_BESIDE_CHARS {
            break;
        }
        length += line.len() + 1;
        if let Some((span, code)) = whole(file, other) {
            if code.len() <= room && !shown.contains(&span) {
                room -= code.len();
                line.push_str(&fenced(&code));
            }
        }
        kept.push((file.sections[other].start, shown_line(file, other), line));
    }
    kept.sort_by_key(|(start, _, _)| *start);
    let text = (kept.iter().map(|(_, _, line)| line.as_str()))
        .collect::<Vec<_>>()
        .join("\n");
    // One span, with the whole list's digest so the same list is not sent
    // again, covering only the first line shown: the bodies and any
    // decorators above it are not shown, so a later prompt still gets a line
    // there naming its stub.
    let first = kept.first()?.1 as u64;
    let span = Span::new(file.path, first, first, &text);
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

/// The line `line` shows of a definition: its first line under any
/// decorators.
fn shown_line(file: &File, at: usize) -> usize {
    let section = &file.sections[at];
    let opening = file.opening(at);
    (section.start..=section.end.min(file.lines.len()))
        .find(|&number| file.lines[number - 1].trim() == opening)
        .unwrap_or(section.start)
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
