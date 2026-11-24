//! Imports named by a constant string.
//!
//! `__import__("concurrent.futures")` and `importlib.import_module("json")`
//! load the module the string names, exactly as an `import` statement does.
//! Libraries use them to put off an import until it is first needed. The
//! screen of a program fed on standard input counted both as code built at
//! run time, which it cannot read, so a probe importing such a library kept
//! its review although nothing about the call is unknown. When the name is a
//! constant, the call is read as the `import` statement it equals: the
//! network, host-module and local-import checks see the module it names.
//!
//! A name built at run time stays dynamic, and so do the modules that reach
//! signals, `eval` or the import machinery through an attribute (`os`,
//! `posix`, `nt`, `signal`, `builtins`, `importlib`, `sys`): the signal and
//! dynamic-code screens find those through their names and `import ... as`
//! aliases, and `p = __import__("os")` would hand them a name they never saw.

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::{Captures, Regex};

/// A call of `__import__` or `import_module` whose only argument is a
/// constant ASCII module name. A non-ASCII name stays dynamic: the local
/// module lookup only resolves ASCII names. A method of some other object
/// (`loader.import_module("x")`) is not the import function.
static CONSTANT_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?m)(?:^|[^.\w])(?P<call>(?:(?:builtins|__builtins__|importlib)\s*\.\s*)?"#,
        r#"(?:__import__|import_module)\s*\(\s*"#,
        r#"(?:"(?P<double>[A-Za-z0-9_][A-Za-z0-9_.]*)"|'(?P<single>[A-Za-z0-9_][A-Za-z0-9_.]*)')\s*\))"#,
    ))
    .unwrap()
});

/// A mention of the import functions' names.
static IMPORT_FUNCTION_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:__import__|import_module)\b").unwrap());

/// `from importlib import ..., import_module, ...`, which binds the name to
/// the import function itself.
static FROM_IMPORTLIB: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)(?:^|[;:])[ \t]*from[ \t]+importlib[ \t]+import[ \t]+\(?([\w, \t]*)").unwrap()
});

/// Code that can rebind an import function without naming it: the builtins
/// or `importlib` namespace written through (`setattr`, `__dict__`,
/// `__setattr__`, `sys.modules`), or a module namespace written by key
/// (`globals()`, `locals()`, `vars()`).
static NAMESPACE_WRITE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\b__dict__\b|\b__setattr__\b|\bsys\s*\.\s*modules\b|\bimport\b[^\n;]*\bmodules\b",
        r"|\b(?:globals|locals)\s*\(|\bvars\s*\(\s*\)|\b__builtins__\b",
    ))
    .unwrap()
});

/// A mention of the modules that hold the import functions.
static IMPORT_HOLDER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:builtins|__builtin__|importlib)\b").unwrap());

/// Whether every mention of `builtins` or `importlib` in `code` is an
/// attribute lookup (`importlib.import_module`) or an import of the module
/// itself. Anything else hands the module to code that may rebind its import
/// function (`setattr(builtins, name, hook)`, `b = builtins`) or binds the
/// name to some other module (`import helpers as importlib`).
fn import_holders_untouched(code: &str) -> bool {
    IMPORT_HOLDER.find_iter(code).all(|found| {
        let after = code[found.end()..].trim_start();
        if after.starts_with('.') {
            return true;
        }
        // An alias escapes the attribute-read check above, so a renamed
        // holder keeps every constant-name import dynamic.
        if after.split_whitespace().next() == Some("as") {
            return false;
        }
        let line_start = code[..found.start()]
            .rfind(['\n', ';'])
            .map_or(0, |at| at + 1);
        let before = code[line_start..found.start()].trim();
        let mut words = before.split_whitespace();
        let statement = matches!(words.next(), Some("import" | "from"));
        statement && words.last() != Some("as")
    })
}

/// Whether the import functions keep their meaning across every one of
/// `sources`, the program and the local modules it loads: a helper module
/// can rebind `builtins.__import__` for the whole process, so one source
/// that may rebind either function keeps every constant-name call dynamic.
pub(super) fn unshadowed<S: AsRef<str>>(sources: &[S]) -> bool {
    sources.iter().all(|source| {
        let source = source.as_ref();
        import_functions_unshadowed(source)
            && import_holders_untouched(source)
            && !NAMESPACE_WRITE.is_match(source)
    })
}

/// Whether every mention of `__import__` and `import_module` in `code` is a
/// call or `from importlib import import_module`. A name is evaluated to
/// its current binding, so once the program assigns, defines, receives or
/// imports something else under either name, a call of it is not known to
/// be an import, and stays dynamic.
fn import_functions_unshadowed(code: &str) -> bool {
    let imported: Vec<(usize, usize)> = FROM_IMPORTLIB
        .captures_iter(code)
        .filter_map(|captures| captures.get(1))
        .filter(|names| {
            !names
                .as_str()
                .split(',')
                .any(|name| name.split_whitespace().nth(1) == Some("as"))
        })
        .map(|names| (names.start(), names.end()))
        .collect();
    IMPORT_FUNCTION_NAME.find_iter(code).all(|found| {
        let called = code[found.end()..].trim_start().starts_with('(');
        let before = code[..found.start()].trim_end();
        let defined = before.ends_with("def") || before.ends_with("class");
        let from_importlib = imported
            .iter()
            .any(|(start, end)| *start <= found.start() && found.end() <= *end);
        (called && !defined) || from_importlib
    })
}

const STAYS_DYNAMIC: &[&str] = &[
    "os",
    "posix",
    "nt",
    "signal",
    "_signal",
    "builtins",
    "__builtin__",
    "importlib",
    "sys",
];

fn module<'t>(captures: &Captures<'t>) -> &'t str {
    captures
        .name("double")
        .or_else(|| captures.name("single"))
        .map_or("", |name| name.as_str())
}

fn read_as_import(module: &str) -> bool {
    let top = module.split('.').next().unwrap_or_default();
    !module.split('.').any(str::is_empty) && !STAYS_DYNAMIC.contains(&top)
}

/// Every module `code` imports by a constant name, for finding the local
/// modules it loads.
pub(super) fn names(code: &str) -> impl Iterator<Item = &str> {
    CONSTANT_IMPORT
        .captures_iter(code)
        .map(|captures| module(&captures))
}

/// The constant-name imports of `code` written as `import` statements, one
/// per line, for the checks that read import statements.
pub(super) fn as_statements(code: &str) -> String {
    names(code)
        .filter(|module| read_as_import(module))
        .map(|module| format!("import {module}\n"))
        .collect()
}

/// Whether a module `code` imports by a constant name is one the screens
/// hold: a host module (`host_module`) or, as the call was held as dynamic
/// code before it was read, a network client.
pub(super) fn held(code: &str, host_module: impl Fn(&str) -> bool) -> bool {
    let statements = as_statements(code);
    !statements.is_empty() && (host_module(&statements) || super::python_network(&statements))
}

/// `code` with each constant-name import replaced by the module it names, so
/// the dynamic-code screen sees only the calls whose module it cannot read.
/// Nothing is replaced when either import function's name may be bound to
/// something else in `code`, or `unshadowed` (see [`unshadowed`]) is false
/// for the program's sources.
pub(super) fn without_constant_imports(code: &str, unshadowed: bool) -> Cow<'_, str> {
    if !unshadowed || !import_functions_unshadowed(code) {
        return Cow::Borrowed(code);
    }
    CONSTANT_IMPORT.replace_all(code, |captures: &Captures<'_>| {
        let (Some(whole), Some(call)) = (captures.get(0), captures.name("call")) else {
            return String::new();
        };
        let lead = &whole.as_str()[..call.start() - whole.start()];
        let module = module(captures);
        let kept = if read_as_import(module) {
            module
        } else {
            call.as_str()
        };
        format!("{lead}{kept}")
    })
}

#[cfg(test)]
mod tests {
    use super::{as_statements, names, unshadowed, without_constant_imports};

    #[test]
    fn a_constant_name_is_read_as_an_import() {
        for (code, statement) in [
            (
                "self._module = __import__('concurrent.futures').futures",
                "import concurrent.futures\n",
            ),
            ("json = importlib.import_module(\"json\")", "import json\n"),
            ("m = import_module('pkg.sub')", "import pkg.sub\n"),
            ("m = builtins.__import__( 'socket' )", "import socket\n"),
        ] {
            assert_eq!(as_statements(code), statement, "{code}");
            assert!(
                !without_constant_imports(code, unshadowed(&[code])).contains("import"),
                "{code}"
            );
        }
    }

    #[test]
    fn a_name_the_scan_cannot_read_stays_dynamic() {
        for code in [
            "m = __import__(name)",
            "m = __import__('x' + name)",
            "m = __import__(f'{name}')",
            "m = __import__('pkg', globals(), locals(), ['run'])",
            "m = importlib.import_module('.sub', package)",
            "m = loader.import_module('json')",
            "p = __import__('os'); p.kill(1, 9)",
            "k = __import__('signal').pthread_kill",
            "b = __import__('builtins'); b.eval(text)",
            "i = importlib.import_module('importlib')",
            "s = __import__('sys')",
            "n = __import__('posix')",
        ] {
            assert_eq!(as_statements(code), "", "{code}");
            assert!(
                without_constant_imports(code, unshadowed(&[code])).contains("import"),
                "{code}"
            );
        }
    }

    #[test]
    fn a_rebinding_in_any_source_keeps_every_call_dynamic() {
        let main = "m = __import__('reboot')";
        for helper in [
            "import builtins, os\nbuiltins.__import__ = os.system",
            "import builtins, os\nsetattr(builtins, '__imp' + 'ort__', os.system)",
            "import importlib, os\nsetattr(importlib, 'import_' + 'module', os.system)",
            "import builtins as b\nb.__dict__['x'] = 1",
            "import builtins as b, os\nsetattr(b, '__imp' + 'ort__', os.system)",
            "import importlib as il, os\nsetattr(il, 'import_' + 'module', os.system)",
            "import os\nb = __builtins__\nb.update(x=os.system)",
            "import sys\nsys.modules['importlib'] = fake",
            "import helpers as importlib",
            "globals()[name] = hook",
        ] {
            assert!(!unshadowed(&[main, helper]), "{helper}");
            assert!(
                without_constant_imports(main, unshadowed(&[main, helper])).contains("__import__"),
                "{helper}"
            );
        }
        for helper in [
            "import importlib\njson = importlib.import_module('json')",
            "from importlib import import_module\nfrom importlib.metadata import version",
            "import builtins\nprint(builtins.len([]))",
        ] {
            assert!(unshadowed(&[main, helper]), "{helper}");
        }
    }

    #[test]
    fn a_non_ascii_module_name_stays_dynamic() {
        for code in [
            "m = __import__('caf\u{e9}')",
            "m = importlib.import_module(\"caf\u{e9}\")",
        ] {
            assert_eq!(without_constant_imports(code, unshadowed(&[code])), code);
            assert_eq!(names(code).count(), 0, "{code}");
        }
    }

    #[test]
    fn a_call_of_a_rebound_import_name_stays_dynamic() {
        for code in [
            "from importlib import import_module as load\nimport_module = lambda _: load('o' + 's')\np = import_module('json')",
            "def import_module(name):\n    return load('os')\np = import_module('json')",
            "def f(import_module):\n    return import_module('json')",
            "from helpers import import_module\np = import_module('json')",
            "from importlib import reload as import_module\np = import_module('json')",
            "for import_module in loaders:\n    import_module('json')",
            "builtins.__import__ = hook\nm = __import__('json')",
            "globals()['__import__'] = hook\nm = __import__('json')",
            "x = lambda __import__: __import__('json')",
        ] {
            assert!(without_constant_imports(code, unshadowed(&[code])).contains("('json')"), "{code}");
        }
        for code in [
            "from importlib import import_module\nj = import_module('json')",
            "from importlib import (reload, import_module)\nj = import_module('json')",
            "import importlib\nj = importlib.import_module('json')",
        ] {
            assert!(
                !without_constant_imports(code, unshadowed(&[code])).contains("('json')"),
                "{code}"
            );
        }
    }

    #[test]
    fn every_constant_name_is_followed_for_local_modules() {
        let code = "a = __import__('os')\nb = import_module('pkg.sub')";
        assert_eq!(names(code).collect::<Vec<_>>(), ["os", "pkg.sub"]);
    }
}
