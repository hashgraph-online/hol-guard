//! Absolute paths in a prompt, whose folders name the machine the prompt was
//! written on rather than the code it asks about.

/// Top folders of a POSIX machine path, matched with their case: macOS
/// writes `/Users`, so a web route such as `/users/{id}` or
/// `/api/orders/{id}` starts with none of them and keeps its words.
const MACHINE_ROOTS: &[&str] = &[
    "Users",
    "Volumes",
    "dev",
    "etc",
    "home",
    "mnt",
    "nix",
    "opt",
    "private",
    "root",
    "srv",
    "tmp",
    "usr",
    "var",
    "workspaces",
];
/// What a path can follow besides a space, such as the `=` of `out=/tmp/a.log`
/// or the `>` of `<output-file>/tmp/a.log</output-file>`.
const OPENERS: &[char] = &['=', '(', '[', '{', '<', '>', '"', '\'', '`', ',', ':', ';'];
/// What ends a path outside quotes, such as the `:` of `/tmp/a.py:parse` or
/// the `<` of a closing tag.
const CLOSERS: &[char] = &[')', ']', '}', '<', '>', '"', '\'', '`', ',', ';', ':'];

/// `prompt` with each absolute machine path blanked: `/tmp/run-1/out.log`,
/// `~/work`, `C:\Users\me`, `C:/Users/me` and `\\server\share`. A path inside
/// quotes runs to the closing quote, spaces and all; any other path ends at a
/// space or a closing mark, so `/tmp/a.py:parse()` keeps `parse`. A `/`
/// stays where each path was, so a backticked `cat /tmp/out.log` still reads
/// as a command.
pub(super) fn without_paths(prompt: &str) -> String {
    let mut out = String::with_capacity(prompt.len());
    let mut rest = prompt;
    let mut before: Option<char> = None;
    while let Some(c) = rest.chars().next() {
        let opens = before.is_none_or(|b| b.is_whitespace() || OPENERS.contains(&b));
        if opens && starts_path(rest) {
            let end = path_end(rest, before);
            let width = rest[..end].chars().count();
            out.push('/');
            out.extend(std::iter::repeat_n(' ', width.saturating_sub(1)));
            before = rest[..end].chars().last();
            rest = &rest[end..];
            continue;
        }
        out.push(c);
        before = Some(c);
        rest = &rest[c.len_utf8()..];
    }
    out
}

fn starts_path(text: &str) -> bool {
    let bytes = text.as_bytes();
    if text.starts_with("~/") || text.starts_with(r"~\") {
        return true;
    }
    if text.starts_with(r"\\") {
        return bytes.get(2).is_some_and(u8::is_ascii_alphanumeric);
    }
    if bytes.len() > 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
    {
        return true;
    }
    let Some(posix) = text.strip_prefix('/') else {
        return false;
    };
    let Some((root, _)) = posix.trim_start_matches('/').split_once('/') else {
        return false;
    };
    MACHINE_ROOTS.contains(&root)
}

/// Where the path at the start of `text` ends. One opened by a quote runs to
/// the closing quote on the same line, when there is one.
fn path_end(text: &str, before: Option<char>) -> usize {
    if let Some(quote) = before.filter(|b| matches!(b, '"' | '\'' | '`')) {
        if let Some(end) = text
            .find([quote, '\n'])
            .filter(|&end| text[end..].starts_with(quote))
        {
            return end;
        }
    }
    // The drive's own `:` in `C:\` does not end it.
    let skip = if text.as_bytes().get(1) == Some(&b':') {
        2
    } else {
        0
    };
    text[skip..]
        .find(|c: char| c.is_whitespace() || CLOSERS.contains(&c))
        .map_or(text.len(), |end| end + skip)
}
