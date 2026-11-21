//! Hand-ported module-loading patterns for runner configuration scripts.
//!
//! Each scanner reproduces one retired `re` pattern over Unicode code points:
//! `\b` borders a word character (`str.isalnum()` or `_`) and `\s` is
//! `str.isspace()`. The optional `module.` prefix never changes a decision,
//! because `\b` also holds between `.` and `require`.

use crate::codex_output_py::py_strip;
use crate::command_option_parsing::{python_is_alphanumeric, python_is_whitespace};

const LOADERS: [&str; 2] = ["require", "import"];

struct Text {
    chars: Vec<char>,
}

impl Text {
    fn word(&self, index: usize) -> bool {
        self.chars
            .get(index)
            .is_some_and(|character| python_is_alphanumeric(*character) || *character == '_')
    }

    /// `\b` immediately before `index`, which starts a word character.
    fn starts_word(&self, index: usize) -> bool {
        index == 0 || !self.word(index - 1)
    }

    /// `\b` immediately after a keyword ending before `index`.
    fn ends_word(&self, index: usize) -> bool {
        !self.word(index)
    }

    fn keyword_at(&self, index: usize, keyword: &str) -> Option<usize> {
        let mut position = index;
        for expected in keyword.chars() {
            if self.chars.get(position) != Some(&expected) {
                return None;
            }
            position += 1;
        }
        Some(position)
    }

    /// End of `\b(?:require|import)` (or any `keywords`) starting at `index`.
    fn loader_at(&self, index: usize, keywords: &[&str]) -> Option<usize> {
        if !self.starts_word(index) {
            return None;
        }
        keywords
            .iter()
            .find_map(|keyword| self.keyword_at(index, keyword))
    }

    fn skip_spaces(&self, mut index: usize) -> usize {
        while self
            .chars
            .get(index)
            .is_some_and(|character| python_is_whitespace(*character))
        {
            index += 1;
        }
        index
    }

    fn at(&self, index: usize, character: char) -> bool {
        self.chars.get(index) == Some(&character)
    }

    fn quote_at(&self, index: usize) -> bool {
        matches!(self.chars.get(index), Some('\'' | '"'))
    }
}

/// `True` when the retired guard raised "computed module loading".
pub(super) fn rejects(source: &str) -> bool {
    let text = Text {
        chars: source.chars().collect(),
    };
    computed_loader(&text)
        || non_literal_call(&text)
        || create_require(&text)
        || commented_loader(&text)
        || non_call_require(&text)
}

/// `\b(?:(?:module\.)?require|import)\s*\(\s*(?!['"])`: backtracking lets
/// `\s*` give up a space, so only a quote right after `(` avoids a match.
fn computed_loader(text: &Text) -> bool {
    (0..text.chars.len()).any(|index| {
        text.loader_at(index, &LOADERS).is_some_and(|end| {
            let open = text.skip_spaces(end);
            text.at(open, '(') && !text.quote_at(open + 1)
        })
    })
}

/// Any `\b(?:require|import)\s*\((?P<argument>[^)]*)\)` match (non-overlapping)
/// whose stripped argument is not one quoted literal.
fn non_literal_call(text: &Text) -> bool {
    let length = text.chars.len();
    let mut index = 0;
    while index < length {
        let Some(end) = text.loader_at(index, &LOADERS) else {
            index += 1;
            continue;
        };
        let open = text.skip_spaces(end);
        if !text.at(open, '(') {
            index += 1;
            continue;
        }
        let Some(close) = (open + 1..length).find(|position| text.chars[*position] == ')') else {
            // No later call can close either.
            return false;
        };
        let argument: String = text.chars[open + 1..close].iter().collect();
        if !literal_argument(py_strip(&argument)) {
            return true;
        }
        index = close + 1;
    }
    false
}

/// `(?P<quote>['"])(?:\\.|(?!\1).)*(?P=quote)` as a full match: every inner
/// quote is escaped by the backslash right before it.
fn literal_argument(argument: &str) -> bool {
    let characters: Vec<char> = argument.chars().collect();
    let Some(&quote) = characters.first() else {
        return false;
    };
    if characters.len() < 2 || !matches!(quote, '\'' | '"') || characters.last() != Some(&quote) {
        return false;
    }
    let interior = &characters[1..characters.len() - 1];
    interior.iter().enumerate().all(|(position, character)| {
        *character != quote || (position > 0 && interior[position - 1] == '\\')
    })
}

/// `\bcreateRequire\b`.
fn create_require(text: &Text) -> bool {
    (0..text.chars.len()).any(|index| {
        text.loader_at(index, &["createRequire"])
            .is_some_and(|end| text.ends_word(end))
    })
}

/// `\b(?:createRequire|(?:module\.)?require|import)\s*(?:/\*.*?\*/|//[^\n]*(?:\n|$))`.
fn commented_loader(text: &Text) -> bool {
    let chars = &text.chars;
    let last_close = (1..chars.len())
        .rev()
        .find(|position| chars[*position - 1] == '*' && chars[*position] == '/')
        .map(|position| position - 1);
    (0..chars.len()).any(|index| {
        text.loader_at(index, &["createRequire", "require", "import"])
            .is_some_and(|end| {
                let slash = text.skip_spaces(end);
                if !text.at(slash, '/') {
                    return false;
                }
                text.at(slash + 1, '/')
                    || (text.at(slash + 1, '*')
                        && last_close.is_some_and(|close| close >= slash + 2))
            })
    })
}

/// `\brequire\b(?!\s*\()`.
fn non_call_require(text: &Text) -> bool {
    (0..text.chars.len()).any(|index| {
        text.loader_at(index, &["require"])
            .is_some_and(|end| text.ends_word(end) && !text.at(text.skip_spaces(end), '('))
    })
}

/// Every `path` group of the static module pattern (non-overlapping, in order):
/// `(?:\bfrom\s+|\b(?:module\.)?require\s*\(\s*|\bimport\s*(?:\(\s*)?)['"](?P<path>[^'"]+)['"]`.
pub(super) fn static_paths(source: &str) -> Vec<String> {
    let text = Text {
        chars: source.chars().collect(),
    };
    let length = text.chars.len();
    let mut paths = Vec::new();
    let mut index = 0;
    while index < length {
        let Some(open) = static_quote(&text, index) else {
            index += 1;
            continue;
        };
        let close = (open + 1..length).find(|position| text.quote_at(*position));
        match close {
            Some(close) if close > open + 1 => {
                paths.push(text.chars[open + 1..close].iter().collect());
                index = close + 1;
            }
            _ => index += 1,
        }
    }
    paths
}

/// The opening quote position when a static loader prefix starts at `index`.
fn static_quote(text: &Text, index: usize) -> Option<usize> {
    if let Some(end) = text.loader_at(index, &["from"]) {
        let quote = text.skip_spaces(end);
        return (quote > end && text.quote_at(quote)).then_some(quote);
    }
    if let Some(end) = text.loader_at(index, &["require"]) {
        let open = text.skip_spaces(end);
        if !text.at(open, '(') {
            return None;
        }
        let quote = text.skip_spaces(open + 1);
        return text.quote_at(quote).then_some(quote);
    }
    let end = text.loader_at(index, &["import"])?;
    let next = text.skip_spaces(end);
    if text.quote_at(next) {
        return Some(next);
    }
    if !text.at(next, '(') {
        return None;
    }
    let quote = text.skip_spaces(next + 1);
    text.quote_at(quote).then_some(quote)
}
