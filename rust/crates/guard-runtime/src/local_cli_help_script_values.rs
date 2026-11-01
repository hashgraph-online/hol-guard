//! The variables that hold a script's first argument, or a list whose items
//! include it, as its code assigns them: `process.argv[2]`, `sys.argv[1]`,
//! `ARGV[0]`, `const [, , command] = process.argv`, `args = sys.argv[1:]`
//! then `args[0]`, `args.shift()`, the positionals a `parseArgs` or
//! `minimist` call returns, and the parameter of a function called with one
//! of them. Variables are tracked by name across the whole file, which is
//! enough for the short dispatch code a script's entry point holds.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;

use super::syntax::{bare, first_argument, sequence, split_assignment, word_list};

/// What an expression holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// The script's first argument.
    First,
    /// A list whose first item is the first argument.
    List,
    Other,
}

/// What a function was called with, for the parameter that receives it.
#[derive(Clone, Copy)]
enum Given {
    First,
    List(usize),
}

/// The argument lists every script starts with, and where its first argument
/// sits in each.
const SEEDS: [(&str, usize); 7] = [
    ("process.argv", 2),
    ("Bun.argv", 2),
    ("sys.argv", 1),
    ("Deno.args", 0),
    ("ARGV", 0),
    ("@ARGV", 0),
    ("$ARGV", 0),
];

/// Bounds on what one read keeps and how deep one expression is followed.
const MAX_NAMES: usize = 256;
const NAME_CHARS: usize = 100;
pub(super) const MAX_DEPTH: usize = 8;

static INDEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(.+?)\[(\d+)\]$").unwrap());

static SLICE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(.+?)(?:\.slice\((\d+)\)|\[(\d+):\]|\.drop\((\d+)\)|\[(\d+)\.\.(?:-1)?\])$")
        .unwrap()
});

static HIDE_BIN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^hideBin\((.+)\)$").unwrap());

/// The first item of a list, read or taken off it.
static FIRST_ITEM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(.+?)(?:\.first|\.shift\(\)|\.shift|\.pop\(0\)|\.at\(0\))$|^shift\s*\(?\s*(@\w+)\s*\)?$",
    )
    .unwrap()
});

/// A statement that takes the first item off a list.
static SHIFTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([A-Za-z_$@][\w$.]*)\.(?:shift\(\)|pop\(0\)|shift\b)|\bshift\s*\(?\s*(@\w+)")
        .unwrap()
});

static PARSE_ARGS_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:await\s+)?(?:util\.)?parseArgs\s*\(").unwrap());

/// `minimist(args)`, `mri(args)` or `yargsParser(args)`: their `_` holds the
/// positionals.
static POSITIONAL_PARSER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:minimist|mri|yargsParser|yargs_parser|parser)\s*\((.*)\)$").unwrap()
});

static DEFINITION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:export\s+)?(?:async\s+)?(?:",
        r"function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)",
        r"|def\s+([A-Za-z_]\w*)\s*\(\s*(?:self\s*,\s*)?([A-Za-z_]\w*)",
        r"|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>",
        r")",
    ))
    .unwrap()
});

static CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*\(").unwrap());

#[derive(Default)]
pub(super) struct Values {
    first: HashSet<String>,
    /// Lists by name, with where the first argument sits in each. `None`
    /// marks a list whose first argument has been taken off it.
    lists: HashMap<String, Option<usize>>,
    /// Names bound to a literal list of words, such as `COMMANDS`.
    constants: HashMap<String, Vec<String>>,
    callees: HashMap<String, Given>,
}

impl Values {
    /// A fresh state that keeps only what a first pass learned about the
    /// functions the script calls with its arguments.
    pub(super) fn with_callees_only(self) -> Self {
        Self {
            callees: self.callees,
            ..Self::default()
        }
    }

    pub(super) fn kind(&self, expression: &str) -> Kind {
        self.kind_at(expression, 0)
    }

    fn kind_at(&self, expression: &str, depth: usize) -> Kind {
        if depth > MAX_DEPTH {
            return Kind::Other;
        }
        let expression = bare(expression);
        if self.first.contains(expression) || self.is_first(expression, depth) {
            Kind::First
        } else if self.offset_at(expression, depth) == Some(0) {
            Kind::List
        } else {
            Kind::Other
        }
    }

    fn is_first(&self, expression: &str, depth: usize) -> bool {
        for separator in [" || ", " ?? ", " or "] {
            if let Some((left, right)) = expression.split_once(separator) {
                return self.kind_at(left, depth + 1) == Kind::First
                    || self.kind_at(right, depth + 1) == Kind::First;
            }
        }
        if let Some(captures) = INDEX.captures(expression) {
            let index = captures[2].parse::<usize>().ok();
            return index.is_some() && self.offset_at(&captures[1], depth + 1) == index;
        }
        if let Some(captures) = FIRST_ITEM.captures(expression) {
            let list = captures
                .get(1)
                .or(captures.get(2))
                .map_or("", |m| m.as_str());
            return self.offset_at(list, depth + 1) == Some(0);
        }
        false
    }

    /// Where the first argument sits in the list an expression names.
    fn offset_at(&self, expression: &str, depth: usize) -> Option<usize> {
        if depth > MAX_DEPTH {
            return None;
        }
        let expression = bare(expression);
        if let Some(offset) = self.lists.get(expression) {
            return *offset;
        }
        if let Some((_, offset)) = SEEDS.iter().find(|(name, _)| *name == expression) {
            return Some(*offset);
        }
        for separator in [" || ", " ?? ", " or "] {
            if let Some((left, right)) = expression.split_once(separator) {
                return self
                    .offset_at(left, depth + 1)
                    .or_else(|| self.offset_at(right, depth + 1));
            }
        }
        if let Some(captures) = SLICE.captures(expression) {
            let skipped: usize = (2..=5)
                .find_map(|group| captures.get(group))
                .and_then(|m| m.as_str().parse().ok())?;
            return self
                .offset_at(&captures[1], depth + 1)?
                .checked_sub(skipped);
        }
        if let Some(captures) = HIDE_BIN.captures(expression) {
            return self.offset_at(&captures[1], depth + 1)?.checked_sub(2);
        }
        None
    }

    /// The words a list literal or a constant holds.
    pub(super) fn words(&self, list: &str) -> Vec<String> {
        word_list(list)
            .or_else(|| self.constants.get(list).cloned())
            .unwrap_or_default()
    }

    /// What one statement assigns, defines or calls, before the line's tests
    /// are read.
    pub(super) fn track(&mut self, line: &str) {
        let statement = line.trim_end_matches(';').trim_end();
        if let Some((target, value)) = split_assignment(statement) {
            self.assign(target, value);
        }
        if let Some(captures) = DEFINITION.captures(statement) {
            let mut groups = (1..=6).filter_map(|group| captures.get(group));
            if let (Some(function), Some(parameter)) = (groups.next(), groups.next()) {
                match self.callees.get(function.as_str()).copied() {
                    Some(Given::First) => self.set_first(parameter.as_str()),
                    Some(Given::List(offset)) => self.set_list(parameter.as_str(), offset),
                    None => {}
                }
            }
        }
        for captures in CALL.captures_iter(statement) {
            let after = captures.get(0).map_or(statement.len(), |m| m.end());
            let argument = first_argument(&statement[after..]);
            let given = match self.kind(argument) {
                Kind::First => Some(Given::First),
                _ => self.offset_at(argument, 0).map(Given::List),
            };
            if let Some(given) = given {
                if self.callees.len() < MAX_NAMES {
                    self.callees.insert(captures[1].to_owned(), given);
                }
            }
        }
    }

    /// What a statement takes off a list, after the line's tests are read:
    /// `args.shift()` once read the first argument, and the list no longer
    /// holds it.
    pub(super) fn consume(&mut self, line: &str) {
        for captures in SHIFTED.captures_iter(line) {
            let Some(list) = captures.get(1).or(captures.get(2)).map(|m| m.as_str()) else {
                continue;
            };
            if let Some(offset) = self.offset_at(list, 0) {
                if self.lists.len() < MAX_NAMES || self.lists.contains_key(list) {
                    self.lists.insert(list.to_owned(), offset.checked_sub(1));
                }
            }
        }
    }

    fn assign(&mut self, target: &str, value: &str) {
        if let Some(items) = sequence(target) {
            let offset = self.offset_at(value, 0);
            for (index, item) in items.into_iter().enumerate() {
                let rest = item.starts_with("...") || item.starts_with('*');
                let name = item.trim_start_matches('.').trim_start_matches('*');
                let name = name.split('=').next().unwrap_or("").trim();
                if name.is_empty() {
                    continue;
                }
                self.forget(name);
                match offset {
                    Some(offset) if rest => {
                        if let Some(remaining) = offset.checked_sub(index) {
                            self.set_list(name, remaining);
                        }
                    }
                    Some(offset) if offset == index => self.set_first(name),
                    _ => {}
                }
            }
            return;
        }
        if let Some(inner) = target.strip_prefix('{').and_then(|t| t.strip_suffix('}')) {
            if PARSE_ARGS_CALL.is_match(value) {
                for item in inner.split(',') {
                    let (key, name) = item.split_once(':').unwrap_or((item, item));
                    if key.trim() == "positionals" {
                        self.set_list(name.split('=').next().unwrap_or("").trim(), 0);
                    }
                }
            }
            return;
        }
        let kind = self.kind(value);
        let offset = self.offset_at(value, 0);
        let words = word_list(value);
        let positionals = POSITIONAL_PARSER
            .captures(value)
            .is_some_and(|captures| self.offset_at(first_argument(&captures[1]), 0) == Some(0));
        self.forget(target);
        if kind == Kind::First {
            self.set_first(target);
        } else if let Some(offset) = offset {
            self.set_list(target, offset);
        } else if PARSE_ARGS_CALL.is_match(value) {
            self.set_list(&format!("{target}.positionals"), 0);
        } else if positionals {
            self.set_list(&format!("{target}._"), 0);
        } else if let Some(words) = words {
            if self.constants.len() < MAX_NAMES {
                self.constants.insert(target.to_owned(), words);
            }
        }
    }

    fn forget(&mut self, name: &str) {
        self.first.remove(name);
        self.lists.remove(name);
        self.constants.remove(name);
    }

    fn set_first(&mut self, name: &str) {
        if name.chars().count() <= NAME_CHARS && self.first.len() < MAX_NAMES {
            self.first.insert(name.to_owned());
        }
    }

    fn set_list(&mut self, name: &str, offset: usize) {
        if !name.is_empty() && name.chars().count() <= NAME_CHARS && self.lists.len() < MAX_NAMES {
            self.lists.insert(name.to_owned(), Some(offset));
        }
    }
}
