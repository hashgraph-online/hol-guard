//! What the file holding a function left to be written imports. Writing the
//! body again, an agent opens the head of the file to learn which names it
//! can use; the import statements in the note save that read.
use super::more::fenced;
use super::rename::stubbed;
use super::{Asked, Entry, File, Pick, Span};

/// Import lines listed, and their length.
const MAX_IMPORT_LINES: usize = 60;
const MAX_IMPORT_CHARS: usize = 1_600;
/// How a top-level line importing names starts.
const IMPORT_STARTS: [&str; 4] = ["import ", "from ", "use ", "pub use "];

/// For the first chosen definition whose body is left to be written, the
/// top-level import statements of its file, a statement spread over lines
/// given whole, unless an earlier prompt of the session was shown them.
pub(super) fn imports(files: &[File], chosen: &[Pick], asked: &Asked) -> Option<(String, Entry)> {
    let file = chosen.iter().find_map(|pick| {
        let file = &files[pick.file];
        (pick.whole && stubbed(file, pick.at)).then_some(file)
    })?;
    let mut kept: Vec<&str> = Vec::new();
    let mut length = 0;
    let mut statement: Vec<&str> = Vec::new();
    let mut open = 0_i64;
    let (mut first, mut last) = (0, 0);
    let mut whole = true;
    for (index, line) in file.lines.iter().enumerate() {
        if statement.is_empty() && !IMPORT_STARTS.iter().any(|start| line.starts_with(start)) {
            continue;
        }
        statement.push(line);
        open += line.matches(['(', '[', '{']).count() as i64;
        open -= line.matches([')', ']', '}']).count() as i64;
        if (open > 0 || line.ends_with('\\')) && statement.len() < MAX_IMPORT_LINES {
            continue;
        }
        let more: usize = statement.iter().map(|line| line.len() + 1).sum();
        if kept.len() + statement.len() > MAX_IMPORT_LINES || length + more > MAX_IMPORT_CHARS {
            whole = false;
            break;
        }
        if kept.is_empty() {
            first = index + 2 - statement.len();
        }
        last = index + 1;
        length += more;
        kept.append(&mut statement);
        open = 0;
    }
    whole &= statement.is_empty();
    if kept.is_empty() {
        return None;
    }
    let code = kept.join("\n");
    let span = Span::new(file.path, first as u64, last as u64, &code);
    if asked.earlier.contains(&span) {
        return None;
    }
    let text = fenced(&code).trim_start_matches('\n').to_owned();
    let title = if whole {
        format!("Imports in {}:", file.path)
    } else {
        format!("First imports in {}:", file.path)
    };
    let entry = Entry {
        code: text.len(),
        text,
        shown: vec![span],
    };
    Some((title, entry))
}
