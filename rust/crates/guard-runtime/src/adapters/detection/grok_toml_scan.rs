//! Text scanning for the Grok user-config merge: header lines, value spans and
//! the TOML string rules those need, plus the comma and whitespace bookkeeping
//! of one array literal. The group logic mirrors how tomlkit lays out an array
//! so an inserted or removed element leaves the same bytes tomlkit would.

/// One `[table]` or `[[array]]` header line: where it starts, its dotted path
/// and whether it opens an array-of-tables element.
#[derive(Clone, Debug)]
pub(crate) struct Header {
    pub(crate) pos: usize,
    pub(crate) path: Vec<String>,
    pub(crate) aot: bool,
}

/// The offset just past the newline that ends the line containing `from`.
pub(crate) fn line_end(b: &[u8], from: usize) -> usize {
    b.get(from..)
        .and_then(|rest| rest.iter().position(|c| *c == b'\n'))
        .map_or(b.len(), |n| from + n + 1)
}

fn parse_header(line: &str) -> Option<(Vec<String>, bool)> {
    let line = line.strip_suffix('\n').unwrap_or(line);
    let rest = line.trim_start_matches([' ', '\t']).strip_prefix('[')?;
    let (aot, rest) = match rest.strip_prefix('[') {
        Some(inner) => (true, inner),
        None => (false, rest),
    };
    let b = rest.as_bytes();
    let mut close = 0;
    while close < b.len() && !matches!(b[close], b']' | b'#') {
        close = match b[close] {
            b'"' | b'\'' => skip_string(b, close),
            _ => close + 1,
        };
    }
    let after = rest.get(close..)?.strip_prefix(']')?;
    let tail = after
        .strip_prefix(']')
        .unwrap_or(after)
        .trim_start_matches([' ', '\t']);
    if !tail.is_empty() && tail != "\r" && !tail.starts_with('#') {
        return None;
    }
    Some((key_path(&rest[..close])?, aot))
}

/// The dotted key a header names, read with TOML's quoting rules so a dot
/// inside a quoted part stays part of that key.
fn key_path(raw: &str) -> Option<Vec<String>> {
    let table: toml::Table = format!("{raw} = 0").parse().ok()?;
    let mut path = Vec::new();
    let mut node = &table;
    loop {
        let mut entries = node.iter();
        let (key, value) = entries.next()?;
        if entries.next().is_some() {
            return None;
        }
        path.push(key.clone());
        match value {
            toml::Value::Table(inner) => node = inner,
            _ => return Some(path),
        }
    }
}

/// The offset just past the string literal that opens at `i`, honoring the
/// multi-line forms and the escapes of basic strings.
fn skip_string(b: &[u8], i: usize) -> usize {
    let quote = b[i];
    let mut j = i + 1;
    if b.get(j) == Some(&quote) && b.get(j + 1) == Some(&quote) {
        j += 2;
        while j < b.len() {
            if quote == b'"' && b[j] == b'\\' {
                j += 2;
            } else if b[j] == quote {
                let run = b[j..].iter().take_while(|c| **c == quote).count();
                j += run;
                if run >= 3 {
                    return j;
                }
            } else {
                j += 1;
            }
        }
        return b.len();
    }
    while j < b.len() && b[j] != quote && b[j] != b'\n' {
        j += if quote == b'"' && b[j] == b'\\' { 2 } else { 1 };
    }
    if b.get(j) == Some(&quote) {
        j += 1;
    }
    j.min(b.len())
}

/// Every header line outside a multi-line value or string, in file order.
pub(crate) fn headers(t: &str) -> Vec<Header> {
    let b = t.as_bytes();
    let (mut out, mut depth, mut pos) = (Vec::new(), 0i32, 0usize);
    while pos < b.len() {
        let end = line_end(b, pos);
        if depth == 0 {
            if let Some((path, aot)) = parse_header(&t[pos..end]) {
                out.push(Header { pos, path, aot });
                pos = end;
                continue;
            }
        }
        let mut i = pos;
        while i < b.len() && b[i] != b'\n' {
            match b[i] {
                b'"' | b'\'' => {
                    i = skip_string(b, i);
                    continue;
                }
                b'#' => {
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
                b'[' | b'{' => depth += 1,
                b']' | b'}' => depth -= 1,
                _ => {}
            }
            i += 1;
        }
        pos = (i + 1).min(b.len());
    }
    out
}

/// The offset just past the value that starts at `p`.
pub(crate) fn value_end(b: &[u8], p: usize) -> usize {
    match b.get(p) {
        Some(b'"' | b'\'') => skip_string(b, p),
        Some(b'[' | b'{') => {
            let (mut depth, mut i) = (0i32, p);
            while i < b.len() {
                match b[i] {
                    b'"' | b'\'' => {
                        i = skip_string(b, i);
                        continue;
                    }
                    b'#' => {
                        i = line_end(b, i);
                        continue;
                    }
                    b'[' | b'{' => depth += 1,
                    b']' | b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            b.len()
        }
        _ => {
            let mut i = p;
            while i < b.len() && !b",]} \t\r\n#".contains(&b[i]) {
                i += 1;
            }
            i
        }
    }
}

/// The span of each element of the array whose brackets are at `a0` and `a1 - 1`.
fn array_values(b: &[u8], a0: usize, a1: usize) -> Vec<(usize, usize)> {
    let (mut spans, mut p) = (Vec::new(), a0 + 1);
    while p + 1 < a1 {
        match b[p] {
            b' ' | b'\t' | b'\r' | b'\n' | b',' => p += 1,
            b'#' => p = line_end(b, p),
            b']' => break,
            _ => {
                let end = value_end(b, p).max(p + 1);
                spans.push((p, end));
                p = end;
            }
        }
    }
    spans
}

/// Render a new string value the way tomlkit does: a basic string with the
/// short escapes, `\u00xx` for other control characters, text kept as is.
pub(crate) fn toml_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '\u{1b}' => out.push_str("\\e"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[derive(Clone, PartialEq)]
enum Val {
    Absent,
    Null,
    Text(String),
}

/// One array group: the whitespace (and comma) before a value, the value, its
/// trailing comma and a trailing comment, as tomlkit splits them.
#[derive(Clone)]
pub(crate) struct Group {
    indent: Option<String>,
    value: Val,
    comma: Option<String>,
    comment: Option<String>,
}

fn has(part: &Option<String>, needle: char) -> bool {
    part.as_deref().is_some_and(|text| text.contains(needle))
}

impl Group {
    fn blank() -> Self {
        Group {
            indent: None,
            value: Val::Absent,
            comma: None,
            comment: None,
        }
    }

    fn is_blank(&self) -> bool {
        self.value == Val::Absent && self.comment.is_none()
    }

    fn text(&self) -> String {
        let value = match &self.value {
            Val::Text(text) => text.as_str(),
            _ => "",
        };
        let parts = [
            self.indent.as_deref(),
            Some(value),
            self.comma.as_deref(),
            self.comment.as_deref(),
        ];
        parts.into_iter().flatten().collect()
    }
}

enum Piece {
    Space(String),
    Comment(String),
    Value(String),
}

/// Split the array literal at `a0..a1` into tomlkit's groups.
pub(crate) fn parse_groups(t: &str, a0: usize, a1: usize) -> Option<Vec<Group>> {
    let b = t.as_bytes();
    let values = array_values(b, a0, a1);
    let (mut pieces, mut p, mut next, mut after_value) = (Vec::new(), a0 + 1, 0, false);
    loop {
        let from = p;
        while matches!(b.get(p), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            p += 1;
        }
        let indent = &t[from..p];
        if indent.contains(['\n', '\r']) {
            pieces.push(Piece::Space(indent.to_string()));
            continue;
        }
        let c = *b.get(p)?;
        if c == b'#' {
            let end = (p..b.len())
                .find(|k| matches!(b[*k], b'\n' | b'\r'))
                .unwrap_or(b.len());
            pieces.push(Piece::Comment(format!("{indent}{}", &t[p..end])));
            p = end;
        } else if !indent.is_empty() {
            pieces.push(Piece::Space(indent.to_string()));
        } else if !after_value && c != b']' {
            let (start, end) = *values.get(next)?;
            next += 1;
            pieces.push(Piece::Value(t[start..end].to_string()));
            (p, after_value) = (end, true);
        } else if after_value && c == b',' {
            p += 1;
            match pieces.last_mut() {
                Some(Piece::Space(space)) => space.push(','),
                _ => pieces.push(Piece::Space(",".to_string())),
            }
            after_value = false;
        } else if c == b']' {
            break;
        } else {
            return None;
        }
    }
    let (mut groups, mut this, mut new_group) = (Vec::new(), Group::blank(), false);
    for piece in pieces {
        match piece {
            Piece::Space(space) if !space.contains(',') || new_group => {
                groups.push(std::mem::replace(
                    &mut this,
                    Group {
                        indent: Some(space),
                        ..Group::blank()
                    },
                ));
                new_group = false;
            }
            Piece::Space(space) => {
                if this.value == Val::Absent {
                    this.value = Val::Null;
                }
                this.comma = Some(space);
            }
            Piece::Comment(comment) => {
                if this.value == Val::Absent {
                    this.value = Val::Null;
                }
                this.comment = Some(comment);
                new_group = true;
            }
            Piece::Value(text) if this.value == Val::Absent => this.value = Val::Text(text),
            Piece::Value(text) => groups.push(std::mem::replace(
                &mut this,
                Group {
                    value: Val::Text(text),
                    ..Group::blank()
                },
            )),
        }
    }
    groups.push(this);
    groups.retain(|g| {
        g.indent.is_some() || g.value != Val::Absent || g.comma.is_some() || g.comment.is_some()
    });
    Some(groups)
}

/// Append `new` as the last element, adding or reusing the separators.
pub(crate) fn arr_append(groups: &mut Vec<Group>, new: String) {
    let mut idx = groups.len();
    let mut default = " ";
    if idx >= 1 && groups[idx - 1].is_blank() {
        idx -= 1;
        if has(&groups[idx].indent, '\n') {
            default = "\n    ";
        }
    }
    let (mut indent, mut comma) = (None, None);
    if idx > 0 {
        let last = &mut groups[idx - 1];
        indent = last.indent.clone();
        let live = last.value != Val::Null;
        if live && default.contains('\n') {
            comma = last.comma.clone();
        }
        if last.comma.is_none() && live && !has(&indent, ',') {
            last.comma = Some(",".to_string());
        }
    }
    if has(&indent, ',') {
        comma = None;
    }
    if indent.is_none() && (idx > 0 || default.contains('\n')) {
        indent = Some(default.to_string());
    }
    groups.insert(
        idx,
        Group {
            indent,
            value: Val::Text(new),
            comma,
            comment: None,
        },
    );
}

/// Remove the `key`-th element, moving its separators the way tomlkit does.
pub(crate) fn arr_remove(groups: &mut Vec<Group>, key: usize) -> Option<()> {
    let idx = groups
        .iter()
        .enumerate()
        .filter(|(_, g)| matches!(g.value, Val::Text(_)))
        .map(|(i, _)| i)
        .nth(key)?;
    let removed = groups.remove(idx);
    if idx == 0 {
        if let Some(first) = groups.first_mut() {
            if first
                .indent
                .as_deref()
                .is_some_and(|i| !i.is_empty() && !i.contains('\n'))
            {
                first.indent = None;
            }
        }
    }
    let (in_indent, in_comma) = (has(&removed.indent, ','), has(&removed.comma, ','));
    if in_indent && in_comma {
        if let Some(next) = groups.get_mut(idx) {
            next.indent = match next.indent.take() {
                None => Some(",".to_string()),
                Some(i) if i.contains(',') => Some(i),
                Some(i) => Some(match i.find('\n') {
                    Some(n) => format!("{},{}", &i[..=n], &i[n + 1..]),
                    None => format!(",{i}"),
                }),
            };
        }
    } else if !in_indent && !in_comma {
        if let Some(next) = groups.iter_mut().skip(idx).find(|g| has(&g.indent, ',')) {
            next.indent = next.indent.as_deref().map(|i| i.replacen(',', "", 1));
        }
    }
    if has(&removed.indent, '\n') {
        if let Some(next) = groups.get_mut(idx) {
            if !has(&next.indent, '\n') {
                next.indent = removed.indent.clone();
            }
        }
    }
    if let Some(last) = groups.last_mut().filter(|g| !g.is_blank()) {
        last.comma = None;
    }
    Some(())
}

/// The array text for `groups`, brackets included.
pub(crate) fn render_groups(groups: &[Group]) -> String {
    let body: String = groups.iter().map(Group::text).collect();
    format!("[{body}]")
}
