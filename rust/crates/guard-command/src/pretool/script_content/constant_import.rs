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
/// constant module name. A method of some other object
/// (`loader.import_module("x")`) is not the import function.
static CONSTANT_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?m)(?:^|[^.\w])(?P<call>(?:(?:builtins|__builtins__|importlib)\s*\.\s*)?"#,
        r#"(?:__import__|import_module)\s*\(\s*"#,
        r#"(?:"(?P<double>\w[\w.]*)"|'(?P<single>\w[\w.]*)')\s*\))"#,
    ))
    .unwrap()
});

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
pub(super) fn without_constant_imports(code: &str) -> Cow<'_, str> {
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
    use super::{as_statements, names, without_constant_imports};

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
            assert!(!without_constant_imports(code).contains("import"), "{code}");
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
            assert!(without_constant_imports(code).contains("import"), "{code}");
        }
    }

    #[test]
    fn every_constant_name_is_followed_for_local_modules() {
        let code = "a = __import__('os')\nb = import_module('pkg.sub')";
        assert_eq!(names(code).collect::<Vec<_>>(), ["os", "pkg.sub"]);
    }
}
