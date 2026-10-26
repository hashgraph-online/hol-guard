//! Oh My Pi `eval` programs in Python that only compute on in-memory values.
//!
//! The kernel gives the program the full Python language and a prelude of
//! file, environment, tool and agent helpers. A program is judged harmless
//! only when it reaches nothing but a short list of pure standard modules and
//! builtins: it imports nothing else, calls no function it did not define or
//! take from that list, names no prelude helper, and touches no dunder
//! attribute. `shutil.which`, the executable probe, is the one function
//! allowed from a module that also holds file operations. Anything else
//! (files, processes, the network, the environment, f-strings that run
//! expressions) is left to the ordinary review.

use std::collections::{HashMap, HashSet};

const MAX_BYTES: usize = 16 * 1024;

const SAFE_MODULES: &[&str] = &[
    "re",
    "json",
    "math",
    "collections",
    "itertools",
    "functools",
    "string",
    "textwrap",
    "datetime",
    "statistics",
    "fnmatch",
    "difflib",
    "unicodedata",
    "decimal",
    "fractions",
    "operator",
    "hashlib",
    "base64",
    "html",
    "typing",
    "dataclasses",
    "enum",
    "copy",
    "bisect",
    "heapq",
    "shlex",
    "pprint",
    "shutil",
];

const SAFE_BUILTINS: &[&str] = &[
    "print",
    "display",
    "len",
    "range",
    "sorted",
    "sum",
    "min",
    "max",
    "str",
    "int",
    "float",
    "bool",
    "list",
    "dict",
    "set",
    "tuple",
    "frozenset",
    "enumerate",
    "zip",
    "map",
    "filter",
    "any",
    "all",
    "abs",
    "round",
    "repr",
    "isinstance",
    "reversed",
    "ord",
    "chr",
    "hex",
    "bin",
    "divmod",
    "pow",
    "bytes",
    "Exception",
    "ValueError",
    "KeyError",
    "IndexError",
    "TypeError",
    "StopIteration",
];

/// Attribute names that reach an imported process or interpreter module, or
/// look up an attribute from text the screen cannot see.
const REFUSED_ATTRIBUTES: &[&str] = &[
    "os",
    "sys",
    "modules",
    "types",
    "weakref",
    "inspect",
    "system",
    "popen",
    "environ",
    "subprocess",
    "builtins",
    "importlib",
    "ctypes",
    "socket",
    "eval",
    "exec",
    "open",
    "format",
    "format_map",
    "vformat",
    "attrgetter",
    "methodcaller",
    "itemgetter",
];

/// The only names a safe module may hand to the program, by `module.name` or
/// `from module import name`. A module can re-export `os`, `sys` or
/// `builtins` under another name, so anything not listed here is refused.
const MODULE_NAMES: &[&str] = &[
    "Any",
    "Callable",
    "Counter",
    "DOTALL",
    "Decimal",
    "Dict",
    "Enum",
    "Fraction",
    "I",
    "IGNORECASE",
    "IntEnum",
    "Iterable",
    "Iterator",
    "List",
    "M",
    "MULTILINE",
    "Mapping",
    "Optional",
    "OrderedDict",
    "S",
    "Sequence",
    "SequenceMatcher",
    "Set",
    "Template",
    "Tuple",
    "Union",
    "VERBOSE",
    "X",
    "accumulate",
    "add",
    "ascii_letters",
    "ascii_lowercase",
    "ascii_uppercase",
    "asdict",
    "astuple",
    "atan",
    "atan2",
    "auto",
    "b16decode",
    "b16encode",
    "b64decode",
    "b64encode",
    "batched",
    "bisect",
    "bisect_left",
    "bisect_right",
    "blake2b",
    "cache",
    "category",
    "ceil",
    "chain",
    "cmp_to_key",
    "comb",
    "combinations",
    "compile",
    "copy",
    "cos",
    "count",
    "cycle",
    "dataclass",
    "date",
    "datetime",
    "dedent",
    "deepcopy",
    "defaultdict",
    "degrees",
    "deque",
    "digits",
    "dropwhile",
    "dumps",
    "e",
    "escape",
    "exp",
    "fabs",
    "factorial",
    "field",
    "fill",
    "filter",
    "findall",
    "finditer",
    "floor",
    "fnmatch",
    "fnmatchcase",
    "fullmatch",
    "gcd",
    "get_close_matches",
    "groupby",
    "heapify",
    "heappop",
    "heappush",
    "hexdigest",
    "hexdigits",
    "hypot",
    "indent",
    "inf",
    "insort",
    "isclose",
    "islice",
    "itemgetter",
    "join",
    "loads",
    "log",
    "log10",
    "log2",
    "lru_cache",
    "match",
    "md5",
    "mean",
    "median",
    "mod",
    "mode",
    "mul",
    "name",
    "namedtuple",
    "ndiff",
    "neg",
    "nlargest",
    "normalize",
    "nsmallest",
    "pairwise",
    "partial",
    "permutations",
    "pformat",
    "pi",
    "pow",
    "pprint",
    "prod",
    "product",
    "pstdev",
    "punctuation",
    "quote",
    "radians",
    "reduce",
    "repeat",
    "search",
    "sha1",
    "sha256",
    "sha512",
    "shorten",
    "sin",
    "split",
    "sqrt",
    "starmap",
    "stdev",
    "sub",
    "subn",
    "takewhile",
    "tan",
    "time",
    "timedelta",
    "timezone",
    "truediv",
    "trunc",
    "unescape",
    "unified_diff",
    "urlsafe_b64decode",
    "urlsafe_b64encode",
    "variance",
    "which",
    "whitespace",
    "wrap",
    "wraps",
    "zip_longest",
];

const KEYWORDS: &[&str] = &[
    "False", "None", "True", "and", "as", "assert", "break", "class", "continue", "def", "elif",
    "else", "except", "finally", "for", "from", "if", "import", "in", "is", "lambda", "not", "or",
    "pass", "raise", "return", "try", "while", "with", "yield", "del", "global", "nonlocal",
];

/// Prelude helpers and names that reach files, processes, the environment or
/// other agents. They are refused wherever they appear, bound or not.
const REFUSED_NAMES: &[&str] = &[
    "env",
    "write",
    "output",
    "tool",
    "agent",
    "completion",
    "wait",
    "judge_batch",
    "workpool",
    "phase",
    "log",
    "bash",
    "edit",
    "grep",
    "glob",
    "find",
    "ls",
    "task",
    "browser",
    "eval",
    "exec",
    "read",
    "open",
    "input",
    "os",
    "sys",
    "subprocess",
    "pathlib",
    "Path",
    "builtins",
    "importlib",
    "ctypes",
    "socket",
    "getattr",
    "setattr",
    "globals",
    "locals",
    "vars",
    "compile",
    "breakpoint",
    "await",
    "async",
    "match",
    "type",
    "super",
    "object",
    "print_",
];

/// The program with comments dropped and every string replaced by `""`, or
/// `None` for anything that could hide code: f-strings, line continuations,
/// non-ASCII outside strings, or an unterminated string.
fn skeleton(code: &str) -> Option<String> {
    let chars: Vec<char> = code.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '#' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '\'' || c == '"' {
            // A string prefix is the identifier letters just written.
            let prefix: String = out
                .chars()
                .rev()
                .take_while(|p| p.is_ascii_alphabetic())
                .collect();
            if prefix.chars().any(|p| matches!(p, 'f' | 'F' | 't' | 'T')) {
                return None;
            }
            if !prefix.is_empty()
                && !prefix
                    .chars()
                    .all(|p| matches!(p, 'r' | 'R' | 'b' | 'B' | 'u' | 'U'))
            {
                return None;
            }
            // The prefix belongs to the string, not to a name.
            out.truncate(out.len() - prefix.len());
            let raw = prefix.contains(['r', 'R']);
            let triple = chars.get(i + 1) == Some(&c) && chars.get(i + 2) == Some(&c);
            i += if triple { 3 } else { 1 };
            loop {
                let ch = *chars.get(i)?;
                if ch == '\\' {
                    // Escapes that decode to other bytes hide the text.
                    if !raw && !matches!(chars.get(i + 1)?, 'n' | 't' | '\\' | '\'' | '"') {
                        return None;
                    }
                    i += 2;
                } else if ch == c
                    && (!triple || (chars.get(i + 1) == Some(&c) && chars.get(i + 2) == Some(&c)))
                {
                    i += if triple { 3 } else { 1 };
                    break;
                } else if ch == '\n' && !triple {
                    return None;
                } else {
                    i += 1;
                }
            }
            out.push_str("\"\"");
            continue;
        } else if c == '\\' || !c.is_ascii() || (c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
        {
            return None;
        } else {
            out.push(c);
            i += 1;
            continue;
        }
    }
    Some(out)
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Every `(position, word)` of the skeleton, numbers skipped.
fn words(code: &str) -> Vec<(usize, &str)> {
    let bytes = code.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_digit() {
            while i < bytes.len() && (is_ident_char(bytes[i] as char) || bytes[i] == b'.') {
                i += 1;
            }
        } else if is_ident_start(c) {
            let start = i;
            while i < bytes.len() && is_ident_char(bytes[i] as char) {
                i += 1;
            }
            found.push((start, &code[start..i]));
        } else {
            i += 1;
        }
    }
    found
}

fn previous_symbol(code: &str, position: usize) -> Option<char> {
    code[..position].chars().rev().find(|c| !c.is_whitespace())
}

/// Names that are modules in some safe module and values in their own.
fn self_named_ok(name: &str, root: &str) -> bool {
    match name {
        "copy" | "bisect" | "fnmatch" | "pprint" => root == name,
        "time" | "datetime" => root == "datetime",
        _ => true,
    }
}

/// Whether the text at `end` reads one listed name off the module `root`.
fn module_member_listed(code: &str, end: usize, root: &str) -> bool {
    let Some(rest) = code[end..].trim_start().strip_prefix('.') else {
        return false;
    };
    let rest = rest.trim_start();
    let name: String = rest.chars().take_while(|c| is_ident_char(*c)).collect();
    if !MODULE_NAMES.contains(&name.as_str()) || !self_named_ok(&name, root) {
        return false;
    }
    // Chaining past a member is for classes of their own root only; any
    // other member may be a module re-exported by another one.
    let after = rest[name.len()..].trim_start();
    !after.starts_with('.')
        || CHAINABLE_CLASSES
            .iter()
            .any(|(module, class)| *module == root && *class == name)
}

const CHAINABLE_CLASSES: &[(&str, &str)] = &[
    ("datetime", "datetime"),
    ("datetime", "date"),
    ("datetime", "timedelta"),
    ("datetime", "timezone"),
    ("datetime", "time"),
    ("itertools", "chain"),
    ("decimal", "Decimal"),
    ("fractions", "Fraction"),
    ("collections", "OrderedDict"),
    ("collections", "Counter"),
];

fn next_symbol(code: &str, end: usize) -> Option<char> {
    code[end..].chars().find(|c| !c.is_whitespace())
}

/// Names the program binds itself: assignment targets, loop and `as`
/// variables, parameters, and the functions and classes it defines.
fn bound_names(code: &str) -> (HashSet<String>, HashSet<String>) {
    let mut bound = HashSet::new();
    let mut callable = HashSet::new();
    let ws = words(code);
    for (index, (position, word)) in ws.iter().enumerate() {
        let end = position + word.len();
        let after = code[end..].trim_start();
        let before = &code[..*position];
        let prev_word = index.checked_sub(1).map(|p| ws[p].1);
        let is_attribute = previous_symbol(code, *position) == Some('.');
        if is_attribute || KEYWORDS.contains(word) {
            continue;
        }
        let line_start = before.rfind('\n').map_or(0, |n| n + 1);
        let in_params = {
            // Inside a `def ...(` or `lambda ...:` header on this line.
            let line = &code[line_start..*position];
            let def_open = line
                .rfind("def ")
                .and_then(|d| line[d..].find('(').map(|o| d + o));
            def_open.is_some_and(|open| !line[open..].contains(')'))
                || line
                    .rfind("lambda")
                    .is_some_and(|l| !line[l..].contains(':'))
        };
        let assigned = after.starts_with('=') && !after.starts_with("==");
        let tuple_target = after.starts_with(',') && line_has_assignment(code, *position);
        let augmented = ["+=", "-=", "*=", "/=", "|=", "&="]
            .iter()
            .any(|op| after.starts_with(op));
        let looped = matches!(prev_word, Some("for" | "as"))
            || (previous_symbol(code, *position) == Some(',') && line_has_for(before, line_start));
        if matches!(prev_word, Some("def" | "class")) {
            callable.insert((*word).to_owned());
            bound.insert((*word).to_owned());
        } else if assigned || tuple_target || augmented || looped || in_params {
            bound.insert((*word).to_owned());
        }
    }
    (bound, callable)
}

fn line_has_assignment(code: &str, position: usize) -> bool {
    let start = code[..position].rfind('\n').map_or(0, |n| n + 1);
    let end = code[position..]
        .find('\n')
        .map_or(code.len(), |n| position + n);
    let line = &code[start..end];
    line.contains('=') && !line.contains("==") || line.contains(" = ")
}

fn line_has_for(before: &str, line_start: usize) -> bool {
    before[line_start..].trim_start().starts_with("for ") || before[line_start..].contains(" for ")
}

/// Whether the imports are all from the pure list, recording what they bind.
fn imports_ok(
    code: &str,
    modules: &mut HashMap<String, String>,
    functions: &mut HashSet<String>,
) -> Option<String> {
    let mut rest = String::new();
    for line in code.lines() {
        let trimmed = line.trim_start();
        if let Some(list) = trimmed.strip_prefix("import ") {
            for item in list.split(',') {
                let mut parts = item.split_whitespace();
                let module = parts.next()?;
                let root = module.split('.').next()?;
                let alias = match (parts.next(), parts.next(), parts.next()) {
                    (None, None, None) => root,
                    (Some("as"), Some(alias), None) if root != "shutil" => alias,
                    _ => return None,
                };
                if !SAFE_MODULES.contains(&root) || !alias.chars().all(is_ident_char) {
                    return None;
                }
                modules.insert(alias.to_owned(), root.to_owned());
            }
            rest.push('\n');
        } else if let Some(tail) = trimmed.strip_prefix("from ") {
            let (module, names) = tail.split_once(" import ")?;
            let root = module.trim().split('.').next()?;
            if !SAFE_MODULES.contains(&root) || root == "shutil" || module.trim().starts_with('.') {
                return None;
            }
            for name in names.split(',') {
                let mut parts = name.split_whitespace();
                let first = parts.next()?;
                // A safe module can re-export `os`, `sys` and their kin.
                if !MODULE_NAMES.contains(&first) || !self_named_ok(first, root) {
                    return None;
                }
                let alias = match (parts.next(), parts.next()) {
                    (None, None) => first,
                    (Some("as"), Some(alias)) => alias,
                    _ => return None,
                };
                if !alias.chars().all(is_ident_char) || alias.is_empty() {
                    return None;
                }
                functions.insert(alias.to_owned());
            }
            rest.push('\n');
        } else {
            rest.push_str(line);
            rest.push('\n');
        }
    }
    Some(rest)
}

pub(super) fn pure_python(code: &str) -> bool {
    if code.len() > MAX_BYTES || code.trim().is_empty() {
        return false;
    }
    let Some(code) = skeleton(code) else {
        return false;
    };
    if code.contains("__") {
        return false;
    }
    let mut modules = HashMap::new();
    let mut functions = HashSet::new();
    let Some(code) = imports_ok(&code, &mut modules, &mut functions) else {
        return false;
    };
    let (bound, defined) = bound_names(&code);
    for (position, word) in words(&code) {
        if previous_symbol(&code, position) == Some('.') {
            // An attribute can lead from a safe module to the process or
            // interpreter it imports (`shlex.os`, `typing.sys.modules`).
            if word.starts_with('_') || REFUSED_ATTRIBUTES.contains(&word) {
                return false;
            }
            continue;
        }
        if KEYWORDS.contains(&word) {
            continue;
        }
        let end = position + word.len();
        if REFUSED_NAMES.contains(&word) {
            return false;
        }
        let is_call = next_symbol(&code, end) == Some('(');
        let defining = code[..position].trim_end().ends_with("def")
            || code[..position].trim_end().ends_with("class");
        if word == "shutil" {
            // Only the executable probe from a module that also holds file
            // operations.
            if !modules.contains_key("shutil") || !code[end..].trim_start().starts_with(".which(") {
                return false;
            }
            continue;
        }
        if let Some(root) = modules.get(word) {
            // A module is only ever the receiver of a listed `module.name`:
            // never passed, assigned, parenthesised or chained into.
            if !module_member_listed(&code, end, root) {
                return false;
            }
            continue;
        }
        if SAFE_BUILTINS.contains(&word) || functions.contains(word) {
            continue;
        }
        if defining {
            continue;
        }
        if is_call {
            // Only a function the program defined itself, or an imported one.
            if !defined.contains(word) {
                return false;
            }
        } else if !bound.contains(word) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::pure_python;

    #[test]
    fn pure_programs_are_accepted() {
        for code in [
            "import shutil\nfor name in ['node', 'git']:\n    print(name, shutil.which(name))\n",
            "import re\ntext = 'a1b22'\nprint(re.findall(r'\\d+', text))\n",
            "import json\nrows = [{'a': 1}]\nprint(json.dumps(rows, indent=2))\n",
            "import datetime\nprint(datetime.datetime.now())",
            "import itertools\nprint(list(itertools.chain.from_iterable([[1], [2]])))",
            "import decimal\nprint(decimal.Decimal.from_float(1.5))",
            "import collections\nprint(collections.OrderedDict.fromkeys('ab'))",
            "from re import sub\nprint(sub('a', 'b', 'abc'))",
            "def total(xs):\n    return sum(x * 2 for x in xs)\nprint(total([1, 2, 3]))\n",
        ] {
            assert!(pure_python(code), "{code:?}");
        }
    }

    #[test]
    fn reaching_programs_are_refused() {
        for code in [
            "import subprocess\nsubprocess.run(['ls'])",
            "import os\nprint(os.environ)",
            "import shutil\nshutil.rmtree('x')",
            "from shutil import which\nprint(which('git'))",
            "print(open('/etc/passwd').read())",
            "print(read('a'))",
            "print(f'{1+1}')",
            "import shlex\nshlex.os.system('x')",
            "import dataclasses\nprint(dataclasses.copy.types.FunctionType)",
            "from dataclasses import copy\nprint(copy)",
            "import dataclasses\nt = dataclasses.copy\nprint(t)",
            "import fnmatch\nprint(fnmatch.re.enum.bltns.getattr)",
            "import enum\nprint((enum).bltns.getattr)",
            "import enum\nm = enum\nprint(m.bltns.getattr)",
            "from enum import bltns as b\nprint(b)",
            "import enum\nprint(enum.bltns.getattr)",
            "from shlex import os as o\no.execvp('sh', ['sh'])",
            "from typing import sys as s\nprint(s)",
            "from dataclasses import inspect as i\nprint(i)",
            "import typing\ntyping.sys.modules['os']",
            "import collections\ncollections._sys.exit(0)",
            "import shlex\nprint('{0.os}'.format(shlex))",
            "x = getattr(str, 'join')",
            "print(().__class__)",
            "import socket",
            "run('ls')",
            "x = 1\nx('a')",
            "print(env('HOME'))",
            "import re as os\nos.system('x')",
            "exec('1')",
            "list(map(bash, ['ls']))",
            "",
        ] {
            assert!(!pure_python(code), "{code:?}");
        }
    }
}
