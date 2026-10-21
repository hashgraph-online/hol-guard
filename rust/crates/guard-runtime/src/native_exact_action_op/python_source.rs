//! The lexical scan behind a `python <script>` launch identity: which modules
//! a source file imports, and whether it can run code those imports do not
//! name.
//!
//! The scan is not a parser. It refuses any text it cannot read, so a false
//! refusal only keeps a launch once-only.

use std::sync::OnceLock;

use regex::Regex;

use replace::call_arguments;
pub(super) use replace::Replaces;

/// One import statement's module: the leading dots of a relative import,
/// the dotted name, and the names a `from` import takes from it.
pub(super) struct Import {
    pub(super) level: usize,
    pub(super) module: String,
    pub(super) names: Vec<String>,
}

/// What the scan read from one source file.
pub(super) struct Scan {
    pub(super) imports: Vec<Import>,
    /// Whether the file can write files: a graph that writes can replace a
    /// module before an import loads it.
    pub(super) writes: bool,
    /// What its `.replace` calls can do, which depends on the whole graph.
    pub(super) replaces: Replaces,
}

fn pattern(cell: &'static OnceLock<Regex>, source: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(source).expect("static pattern"))
}

/// Names that evaluate strings, reach the import system or interpreter
/// internals, start or replace processes, load native code, or load tests
/// by name. Matched against code, with literal bodies and comments blanked.
pub(super) fn forbidden() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        concat!(
            r"\b(?:exec|eval|execfile|__import__|getattr|setattr|delattr|globals|locals|vars|breakpoint)\b",
            r"|(?:^|[^.\w])(?:compile|help)\s*\(",
            r"|\bsys\s*\.\s*(?:modules|path|meta_path|path_hooks|path_importer_cache|settrace|setprofile|addaudithook|_getframe)\b",
            r"|\b(?:_getframe|f_globals|f_locals|f_builtins|CodeType|FunctionType|attrgetter|methodcaller)\b",
            r"|\b(?:system|popen|startfile|fork|forkpty|posix_spawnp?|spawn[lv]p?e?|exec[lv]p?e?|create_subprocess_\w+)\b",
            r"|\b(?:load_extension|enable_load_extension)\b|\blogging\s*\.\s*config\b|\bunittest\s*\.\s*mock\b",
            // `warnings` imports the category a filter string names.
            r"|\b(?:_setoption|_getcategory)\b",
            r"|\b(?:discover|loadTestsFromName|loadTestsFromNames)\b|\bmodule\s*=\s*None\b",
            // Annotation helpers evaluate strings, which a script can build at run time.
            r"|\b(?:get_type_hints|ForwardRef|evaluate_forward_ref|_evaluate|get_annotations|call_annotate_function|call_evaluate_function)\b",
            r"|\bCGIHTTPRequestHandler\b",
        ),
    )
}

/// Dunder names that reach interpreter internals. Matched against the whole
/// text, because a format string reaches them through `{0.__class__}`.
fn forbidden_dunder() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        r"__(?:builtins|dict|class|subclasses|globals|code|closure|func|self|loader|spec|path|bases|base|mro|getattribute|reduce|reduce_ex|setstate|import|annotations|annotate)__",
    )
}

fn writes_files() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        concat!(
            r"\.\s*write(?:_text|_bytes|lines)?\s*\(|\bos\s*\.\s*replace\s*\(",
            r"|\b(?:rename|renames|remove|unlink|rmtree|copy|copy2|copyfile|copytree|move|symlink|symlink_to|hardlink_to|link|truncate|makedirs|mkdir|rmdir|removedirs|touch|extract|extractall|unpack_archive|writestr)\s*\(",
            // Writable handles and mappings that change a file without `open`.
            r"|\b(?:FileIO|mmap|pwrite|pwritev|writev|ftruncate|sendfile|copy_file_range|splice|chmod|lchmod|chown|lchown|utime|mkfifo|mknod)\b",
        ),
    )
}

fn open_call() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"(\.\s*)?\bopen\s*\(")
}

/// A mode literal that opens a file only for reading.
fn reading_mode() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r#"^(?:'[rbtU]+'|"[rbtU]+")$"#)
}

/// Whether some `open` call in `code` (with `source` its unblanked text) can
/// write: every mode it passes must be a literal that only reads. A function
/// `open` takes the path first; a method (`Path.open`, `gzip.open`) may take
/// the mode first, so each of its arguments must be such a literal.
fn opens_for_writing(code: &str, source: &str) -> bool {
    open_call().captures_iter(code).any(|captures| {
        let method = captures.get(1).is_some();
        let start = captures.get(0).map_or(0, |found| found.end());
        let Some(arguments) = call_arguments(code, start) else {
            return true;
        };
        let mut positional = 0usize;
        arguments.into_iter().any(|range| {
            let argument = code[range.clone()].trim();
            let text = source[range].trim();
            if argument.is_empty() {
                return false;
            }
            if argument.starts_with('*') {
                return true;
            }
            if let Some((name, _)) = argument.split_once('=') {
                let name = name.trim();
                if name
                    .bytes()
                    .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
                {
                    let value = text.split_once('=').map_or("", |(_, value)| value.trim());
                    return match name {
                        "mode" => !reading_mode().is_match(value),
                        "opener" | "flags" => true,
                        _ => false,
                    };
                }
            }
            positional += 1;
            (method || positional > 1) && !reading_mode().is_match(text)
        })
    })
}

fn from_statement() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        r"^from[ \t]+(\.*)[ \t]*([A-Za-z_][\w.]*)?[ \t]+import[ \t]*(\([^)]*\)|[^\n;]*)",
    )
}

fn import_statement() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"^import[ \t]+([^\n;]*)")
}

fn keyword_from() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"\bfrom\b")
}

fn keyword_import() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"\bimport\b")
}

fn dotted() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        r"^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)(?:[ \t]+as[ \t]+[A-Za-z_]\w*)?$",
    )
}

fn imported_name() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"^([A-Za-z_]\w*)(?:\s+as\s+[A-Za-z_]\w*)?$")
}

fn coding_declaration() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"^[ \t\x0c]*#.*?coding[:=][ \t]*([-\w.]+)")
}

/// The end of a plain single-line literal that opens at `start` with
/// `quote` inside a replacement field, or `None` when it does not end on its
/// line or holds a replacement field of its own.
fn plain_literal_end(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut cursor = start + 1;
    loop {
        match *bytes.get(cursor)? {
            b'\\' => cursor += 2,
            b'\n' | b'\r' | b'{' => return None,
            current if current == quote => return Some(cursor + 1),
            _ => cursor += 1,
        }
    }
}

/// The literal prefix (`r`, `b`, `f`, ...) that ends at `index`, lowercased,
/// or `None` for an identifier that cannot prefix a literal.
fn literal_prefix(text: &str, index: usize) -> Option<String> {
    let start = text[..index]
        .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .map_or(0, |at| at + 1);
    let prefix = text[start..index].to_ascii_lowercase();
    ["", "r", "u", "b", "f", "br", "rb", "fr", "rf"]
        .contains(&prefix.as_str())
        .then_some(prefix)
}

/// `text` with every literal body and comment blanked to spaces (newlines
/// kept) and the replacement fields of formatted literals kept as code, or
/// `None` for text the scan cannot read: an unterminated literal, a bare
/// carriage return, a non-ASCII character outside literals and comments, or
/// a replacement field holding a line break, comment, backslash, its own
/// quote or a nested replacement field.
fn code_only(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\r' && bytes.get(index + 1) != Some(&b'\n') {
            // Python ends a line at a bare carriage return; the scan would not.
            return None;
        }
        if byte == b'#' {
            while index < bytes.len() && bytes[index] != b'\n' {
                if bytes[index] == b'\r' && bytes.get(index + 1) != Some(&b'\n') {
                    return None;
                }
                out[index] = b' ';
                index += 1;
            }
            continue;
        }
        if byte != b'\'' && byte != b'"' {
            if !byte.is_ascii() {
                return None;
            }
            index += 1;
            continue;
        }
        let formatted = literal_prefix(text, index)?.contains('f');
        let triple = bytes.get(index..index + 3) == Some(&[byte, byte, byte][..]);
        let quote_len = if triple { 3 } else { 1 };
        let mut cursor = index + quote_len;
        let mut depth = 0usize;
        loop {
            let current = *bytes.get(cursor)?;
            if depth > 0 {
                match current {
                    b'}' => depth -= 1,
                    b'{' => depth += 1,
                    b'\'' | b'"' if current != byte => {
                        let end = plain_literal_end(bytes, cursor, current)?;
                        for slot in &mut out[cursor + 1..end - 1] {
                            *slot = b' ';
                        }
                        cursor = end;
                        continue;
                    }
                    b'\'' | b'"' | b'\n' | b'\r' | b'#' | b'\\' => return None,
                    other if !other.is_ascii() => return None,
                    _ => {}
                }
                cursor += 1;
                continue;
            }
            match current {
                b'\\' => {
                    // Raw literals still cannot end on an escaped quote.
                    for slot in out.iter_mut().skip(cursor).take(2) {
                        if *slot != b'\n' {
                            *slot = b' ';
                        }
                    }
                    cursor += 2;
                    continue;
                }
                b'\n' if !triple => return None,
                b'{' if formatted => {
                    out[cursor] = b' ';
                    if bytes.get(cursor + 1) == Some(&b'{') {
                        out[cursor + 1] = b' ';
                        cursor += 2;
                    } else {
                        depth = 1;
                        cursor += 1;
                    }
                    continue;
                }
                _ if current == byte
                    && (!triple
                        || bytes.get(cursor..cursor + 3) == Some(&[byte, byte, byte][..])) =>
                {
                    break;
                }
                b'\n' => {}
                _ => out[cursor] = b' ',
            }
            cursor += 1;
        }
        index = cursor + quote_len;
    }
    String::from_utf8(out).ok()
}

/// `source` with literal bodies and comments blanked, or `None` when it
/// declares another encoding, reaches interpreter internals through a dunder
/// name, or has a shape the scan cannot read.
pub(super) fn readable(source: &str) -> Option<String> {
    for line in source.lines().take(2) {
        if let Some(captures) = coding_declaration().captures(line) {
            let codec = captures[1].to_ascii_lowercase().replace('_', "-");
            if !matches!(codec.as_str(), "utf-8" | "utf8" | "ascii") {
                return None;
            }
        }
    }
    if forbidden_dunder().is_match(source) {
        return None;
    }
    let code = code_only(source)?;
    // A line continuation hides a statement's shape from the scan.
    if code.contains("\\\n") || code.contains("\\\r\n") {
        return None;
    }
    Some(code)
}

/// Every import `source` makes and whether it writes files, or `None` when
/// it can run code its imports do not name or the scan cannot read it.
pub(super) fn scan(source: &str) -> Option<Scan> {
    let code = readable(source)?;
    if forbidden().is_match(&code) {
        return None;
    }
    let replaces = replace::replaces(&code);
    Some(Scan {
        imports: imports_in(&code)?,
        writes: writes_files().is_match(&code)
            || opens_for_writing(&code, source)
            || replaces.writes(),
        replaces,
    })
}

/// The import statements in `code`, as `readable` returns it; `None` when
/// one takes names the text does not spell out.
pub(super) fn imports_in(code: &str) -> Option<Vec<Import>> {
    let mut imports = Vec::new();
    let mut covered: Vec<(usize, usize)> = Vec::new();
    for found in keyword_from().find_iter(code) {
        // `raise ... from` and `yield from` are not imports.
        let Some(captures) = from_statement().captures(&code[found.start()..]) else {
            continue;
        };
        let level = captures[1].len();
        let module = captures.get(2).map_or("", |m| m.as_str()).to_owned();
        if level == 0 && module.is_empty() {
            return None;
        }
        let clause = captures[3].trim();
        let clause = clause
            .strip_prefix('(')
            .map_or(clause, |inner| inner.strip_suffix(')').unwrap_or(inner));
        let mut names = Vec::new();
        for item in clause.split(',').map(str::trim) {
            if !item.is_empty() {
                // `*` brings in names the text never spells out.
                names.push(imported_name().captures(item)?[1].to_owned());
            }
        }
        if names.is_empty() {
            return None;
        }
        covered.push((found.start(), found.start() + captures[0].len()));
        imports.push(Import {
            level,
            module,
            names,
        });
    }
    for found in keyword_import().find_iter(code) {
        if covered
            .iter()
            .any(|(start, end)| (*start..*end).contains(&found.start()))
        {
            continue;
        }
        let captures = import_statement().captures(&code[found.start()..])?;
        for item in captures[1].split(',').map(str::trim) {
            imports.push(Import {
                level: 0,
                module: dotted().captures(item)?[1].to_owned(),
                names: Vec::new(),
            });
        }
    }
    Some(imports)
}

#[path = "python_replace.rs"]
mod replace;
#[cfg(test)]
#[path = "python_source_tests.rs"]
mod tests;
