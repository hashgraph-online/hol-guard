//! PyYAML's `yaml.dump(doc, default_flow_style=False, sort_keys=False)` for a
//! JSON document: block collections, empty ones in flow style, and each
//! scalar in the style PyYAML's emitter picks, folded at 80 columns.
//!
//! The state machine follows `yaml/emitter.py` step for step, so column,
//! indentation and whitespace bookkeeping match the bytes PyYAML writes.

use crate::pyjson::PyVal;

#[path = "pyyaml_dump_scalar.rs"]
mod scalar;
use scalar::{escape, scalar_text};

const WIDTH: usize = 80;
const INDENT: usize = 2;
const TAG_STR: &str = "tag:yaml.org,2002:str";

fn is_break(ch: char) -> bool {
    matches!(ch, '\n' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

fn is_space_or_break(ch: char) -> bool {
    matches!(
        ch,
        '\0' | ' ' | '\t' | '\r' | '\n' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// `yaml.dump(value, default_flow_style=False, sort_keys=False)`.
pub(crate) fn dump(value: &PyVal) -> String {
    let mut emitter = Emitter {
        out: String::new(),
        column: 0,
        whitespace: true,
        indention: true,
        indent: None,
        indents: Vec::new(),
        open_ended: false,
    };
    emitter.node(value, true, false, false);
    emitter.write_indent();
    if emitter.open_ended {
        emitter.write_indicator("...", true, false, false);
        emitter.write_indent();
    }
    emitter.out
}

/// What `analyze_scalar` decides for a block-context scalar, with
/// `allow_unicode` unset.
struct Analysis {
    empty: bool,
    multiline: bool,
    block_plain: bool,
    single_quoted: bool,
}

fn analyze(text: &[char]) -> Analysis {
    if text.is_empty() {
        return Analysis {
            empty: true,
            multiline: false,
            block_plain: true,
            single_quoted: true,
        };
    }
    let len = text.len();
    let mut block_indicators =
        text.starts_with(&['-', '-', '-']) || text.starts_with(&['.', '.', '.']);
    let mut line_breaks = false;
    let mut special = false;
    let mut leading_space = false;
    let mut leading_break = false;
    let mut trailing_space = false;
    let mut trailing_break = false;
    let mut break_space = false;
    let mut space_break = false;
    let mut preceded_by_whitespace = true;
    let mut followed_by_whitespace = len == 1 || is_space_or_break(text[1]);
    let mut previous_space = false;
    let mut previous_break = false;
    for (index, &ch) in text.iter().enumerate() {
        if index == 0 {
            if "#,[]{}&*!|>'\"%@`".contains(ch) {
                block_indicators = true;
            }
            if matches!(ch, '?' | ':' | '-') && followed_by_whitespace {
                block_indicators = true;
            }
        } else {
            if ch == ':' && followed_by_whitespace {
                block_indicators = true;
            }
            if ch == '#' && preceded_by_whitespace {
                block_indicators = true;
            }
        }
        if is_break(ch) {
            line_breaks = true;
        }
        if !(ch == '\n' || (' '..='~').contains(&ch)) {
            special = true;
        }
        if ch == ' ' {
            leading_space |= index == 0;
            trailing_space |= index == len - 1;
            break_space |= previous_break;
            previous_space = true;
            previous_break = false;
        } else if is_break(ch) {
            leading_break |= index == 0;
            trailing_break |= index == len - 1;
            space_break |= previous_space;
            previous_space = false;
            previous_break = true;
        } else {
            previous_space = false;
            previous_break = false;
        }
        preceded_by_whitespace = is_space_or_break(ch);
        followed_by_whitespace = index + 2 >= len || is_space_or_break(text[index + 2]);
    }
    let mut block_plain = true;
    let mut single_quoted = true;
    if leading_space || leading_break || trailing_space || trailing_break {
        block_plain = false;
    }
    if break_space || space_break || special {
        block_plain = false;
        single_quoted = false;
    }
    if line_breaks || block_indicators {
        block_plain = false;
    }
    Analysis {
        empty: false,
        multiline: line_breaks,
        block_plain,
        single_quoted,
    }
}

#[derive(PartialEq)]
enum Style {
    Plain,
    Single,
    Double,
}

struct Emitter {
    out: String,
    column: usize,
    whitespace: bool,
    indention: bool,
    indent: Option<usize>,
    indents: Vec<Option<usize>>,
    open_ended: bool,
}

impl Emitter {
    fn increase_indent(&mut self, flow: bool, indentless: bool) {
        self.indents.push(self.indent);
        match self.indent {
            None => self.indent = Some(if flow { INDENT } else { 0 }),
            Some(indent) if !indentless => self.indent = Some(indent + INDENT),
            Some(_) => {}
        }
    }

    fn pop_indent(&mut self) {
        self.indent = self.indents.pop().flatten();
    }

    fn write(&mut self, chunk: &[char]) {
        self.column += chunk.len();
        self.out.extend(chunk);
    }

    fn write_indicator(
        &mut self,
        indicator: &str,
        need_whitespace: bool,
        whitespace: bool,
        indention: bool,
    ) {
        if !self.whitespace && need_whitespace {
            self.out.push(' ');
            self.column += 1;
        }
        self.out.push_str(indicator);
        self.column += indicator.chars().count();
        self.whitespace = whitespace;
        self.indention = self.indention && indention;
        self.open_ended = false;
    }

    fn write_indent(&mut self) {
        let indent = self.indent.unwrap_or(0);
        if !self.indention || self.column > indent || (self.column == indent && !self.whitespace) {
            self.write_line_break('\n');
        }
        if self.column < indent {
            self.whitespace = true;
            self.out
                .extend(std::iter::repeat_n(' ', indent - self.column));
            self.column = indent;
        }
    }

    fn write_line_break(&mut self, ch: char) {
        self.whitespace = true;
        self.indention = true;
        self.column = 0;
        self.out.push(ch);
    }

    fn write_breaks(&mut self, breaks: &[char]) {
        if breaks.first() == Some(&'\n') {
            self.write_line_break('\n');
        }
        for &ch in breaks {
            self.write_line_break(ch);
        }
    }

    fn node(&mut self, value: &PyVal, root: bool, mapping: bool, simple_key: bool) {
        match value {
            PyVal::List(items) if items.is_empty() => self.empty_flow("[", "]"),
            PyVal::Dict(entries) if entries.is_empty() => self.empty_flow("{", "}"),
            PyVal::List(items) => self.block_sequence(items, mapping),
            PyVal::Dict(entries) => self.block_mapping(entries),
            scalar => {
                let (text, plain_implicit) = scalar_text(scalar);
                self.scalar(&text, plain_implicit, root, simple_key);
            }
        }
    }

    fn empty_flow(&mut self, open: &str, close: &str) {
        self.write_indicator(open, true, true, false);
        self.write_indicator(close, false, false, false);
    }

    fn block_sequence(&mut self, items: &[PyVal], mapping: bool) {
        let indentless = mapping && !self.indention;
        self.increase_indent(false, indentless);
        for item in items {
            self.write_indent();
            self.write_indicator("-", true, false, true);
            self.node(item, false, false, false);
        }
        self.pop_indent();
    }

    fn block_mapping(&mut self, entries: &[(String, PyVal)]) {
        self.increase_indent(false, false);
        for (key, value) in entries {
            self.write_indent();
            let chars: Vec<char> = key.chars().collect();
            let analysis = analyze(&chars);
            let key_node = PyVal::Str(key.clone());
            if chars.len() < 128 && !analysis.empty && !analysis.multiline {
                self.node(&key_node, false, true, true);
                self.write_indicator(":", false, false, false);
            } else {
                self.write_indicator("?", true, false, true);
                self.node(&key_node, false, true, false);
                self.write_indent();
                self.write_indicator(":", true, false, true);
            }
            self.node(value, false, true, false);
        }
        self.pop_indent();
    }

    fn scalar(&mut self, text: &str, plain_implicit: bool, root: bool, simple_key: bool) {
        self.increase_indent(true, false);
        let chars: Vec<char> = text.chars().collect();
        let analysis = analyze(&chars);
        let style = if plain_implicit
            && !(simple_key && (analysis.empty || analysis.multiline))
            && analysis.block_plain
        {
            Style::Plain
        } else if analysis.single_quoted && !(simple_key && analysis.multiline) {
            Style::Single
        } else {
            Style::Double
        };
        let split = !simple_key;
        match style {
            Style::Plain => self.write_plain(&chars, split, root),
            Style::Single => self.write_single_quoted(&chars, split),
            Style::Double => self.write_double_quoted(&chars, split),
        }
        self.pop_indent();
    }

    fn write_plain(&mut self, text: &[char], split: bool, root: bool) {
        if root {
            self.open_ended = true;
        }
        if text.is_empty() {
            return;
        }
        if !self.whitespace {
            self.out.push(' ');
            self.column += 1;
        }
        self.whitespace = false;
        self.indention = false;
        let (mut spaces, mut breaks) = (false, false);
        let (mut start, mut end) = (0, 0);
        while end <= text.len() {
            let ch = text.get(end).copied();
            if spaces {
                if ch != Some(' ') {
                    if start + 1 == end && self.column > WIDTH && split {
                        self.write_indent();
                        self.whitespace = false;
                        self.indention = false;
                    } else {
                        self.write(&text[start..end]);
                    }
                    start = end;
                }
            } else if breaks {
                if !ch.is_some_and(is_break) {
                    self.write_breaks(&text[start..end]);
                    self.write_indent();
                    self.whitespace = false;
                    self.indention = false;
                    start = end;
                }
            } else if ch.is_none_or(|ch| ch == ' ' || is_break(ch)) {
                self.write(&text[start..end]);
                start = end;
            }
            if let Some(ch) = ch {
                spaces = ch == ' ';
                breaks = is_break(ch);
            }
            end += 1;
        }
    }

    fn write_single_quoted(&mut self, text: &[char], split: bool) {
        self.write_indicator("'", true, false, false);
        let (mut spaces, mut breaks) = (false, false);
        let (mut start, mut end) = (0, 0);
        while end <= text.len() {
            let ch = text.get(end).copied();
            if spaces {
                if ch != Some(' ') {
                    if start + 1 == end
                        && self.column > WIDTH
                        && split
                        && start != 0
                        && end != text.len()
                    {
                        self.write_indent();
                    } else {
                        self.write(&text[start..end]);
                    }
                    start = end;
                }
            } else if breaks {
                if !ch.is_some_and(is_break) {
                    self.write_breaks(&text[start..end]);
                    self.write_indent();
                    start = end;
                }
            } else if ch.is_none_or(|ch| ch == ' ' || ch == '\'' || is_break(ch)) && start < end {
                self.write(&text[start..end]);
                start = end;
            }
            if ch == Some('\'') {
                self.out.push_str("''");
                self.column += 2;
                start = end + 1;
            }
            if let Some(ch) = ch {
                spaces = ch == ' ';
                breaks = is_break(ch);
            }
            end += 1;
        }
        self.write_indicator("'", false, false, false);
    }

    fn write_double_quoted(&mut self, text: &[char], split: bool) {
        self.write_indicator("\"", true, false, false);
        let (mut start, mut end) = (0, 0);
        while end <= text.len() {
            let ch = text.get(end).copied();
            let escaped = ch.is_none_or(|ch| {
                matches!(
                    ch,
                    '"' | '\\' | '\u{85}' | '\u{2028}' | '\u{2029}' | '\u{FEFF}'
                ) || !(' '..='~').contains(&ch)
            });
            if escaped {
                if start < end {
                    self.write(&text[start..end]);
                    start = end;
                }
                if let Some(ch) = ch {
                    let data = escape(ch);
                    self.column += data.len();
                    self.out.push_str(&data);
                    start = end + 1;
                }
            }
            let pending = end as isize - start as isize;
            if 0 < end
                && end + 1 < text.len()
                && (ch == Some(' ') || start >= end)
                && self.column as isize + pending > WIDTH as isize
                && split
            {
                if start < end {
                    self.write(&text[start..end]);
                    start = end;
                }
                self.out.push('\\');
                self.column += 1;
                self.write_indent();
                self.whitespace = false;
                self.indention = false;
                if text[start] == ' ' {
                    self.out.push('\\');
                    self.column += 1;
                }
            }
            end += 1;
        }
        self.write_indicator("\"", false, false, false);
    }
}

#[cfg(test)]
#[path = "pyyaml_dump_tests.rs"]
mod tests;
