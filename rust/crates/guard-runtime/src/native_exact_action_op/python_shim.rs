//! Meta-path shims that virtualenv, uv and setuptools install through a
//! `.pth` file. Their finders use import machinery the scan refuses, but they
//! only redirect the `SHIMMED` packages. A shim is bound by content when no
//! name in it can load code the proof does not bind, and what it imports by
//! name is bound as the graph binds any startup import.
//!
//! A shim may load a redirected package by literal name only inside a
//! function. Such a function, and any function that calls it, is a loader:
//! code that runs while `site` starts may not call one, and neither may an
//! import-protocol method, which the import system calls for every import.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::{Captures, Regex};

use super::super::super::python_modules::STANDARD_MODULES;
use super::super::super::python_source::{forbidden, imports_in, readable, Import};

pub(super) const SHIMS: [&str; 2] = ["_virtualenv", "_distutils_hack"];
pub(super) const SHIMMED: [&str; 3] = ["distutils", "setuptools", "pip"];
/// What a shim may read or set attributes on by name: itself, its own
/// classes, and the loader it wraps.
const SHIM_TARGETS: [&str; 3] = ["self", "cls", "spec.loader"];
/// Marks a literal `import_module` until the layout places it.
const LAZY: &str = "_lazy_import_";

/// What a shim imports, the functions in it that load a module, and its code
/// as `references` returns it.
pub(super) struct Shim {
    pub(super) imports: Vec<Import>,
    pub(super) loaders: BTreeSet<String>,
    pub(super) code: String,
}

/// A function in a shim, and for a method the parameter after the first.
struct Function {
    name: String,
    parameter: Option<String>,
}

fn pattern(cell: &'static OnceLock<Regex>, source: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(source).expect("static pattern"))
}

/// `__import__('name')` with a literal name, as `.pth` import lines write it.
pub(super) fn literal_import() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        r#"__import__\(\s*(?:'([A-Za-z_][\w.]*)'|"([A-Za-z_][\w.]*)")\s*\)"#,
    )
}

/// `import_module('name')` with a literal name.
fn literal_import_module() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        r#"\bimport_module\([ \t]*(?:'([A-Za-z_][\w.]*)'|"([A-Za-z_][\w.]*)")[ \t]*\)"#,
    )
}

/// Names that evaluate strings, read or write files, start programs, or
/// load a module from a name or path the text does not spell out. Matched as words
/// against code with literal bodies and comments blanked, so a reference is
/// refused as well as a call.
fn shim_refused() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        concat!(
            r"\b(?:exec|eval|compile|execfile|__import__|open|read_text|read_bytes|loads|system|popen",
            r"|import_module|exec_module|load_module|load_source|spec_from_file_location|module_from_spec",
            r"|get_code|source_to_code|run_path|run_module|runsource|runcode|runpy|zipimport|pkgutil",
            r"|SourceFileLoader|SourcelessFileLoader|ExtensionFileLoader|FunctionType|CodeType",
            r"|getattr|setattr|delattr|globals|vars|builtins|attrgetter|methodcaller",
            r"|rename|renames|unlink|rmtree|symlink|symlink_to|hardlink_to|link|truncate|ftruncate",
            r"|makedirs|mkdir|rmdir|removedirs|copyfile|copytree|copy2|move|write|writelines|write_text|write_bytes",
            r"|writestr|FileIO|mmap|chmod|chown|utime|extractall|unpack_archive",
            r"|subprocess|ctypes|marshal|pickle|codecs)\b|\.\s*replace\b",
        ),
    )
}

fn method_definition() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"\bdef[ \t]+\w+")
}

/// A function's name and, for a method, the parameter after the first.
fn definition() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        r"^(?:async[ \t]+)?def[ \t]+(\w+)(?:[ \t]*\([ \t]*\w+[ \t]*,[ \t]*(\w+))?",
    )
}

/// An attribute read by name, which calls whatever the name selects. The
/// name is captured only when the argument is a bare variable; a name the
/// call slices, joins or replaces can select any method.
fn dispatch() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"\bgetattr\(\s*([\w.]+)\s*,\s*(?:(\w+)\s*[,)])?")
}

/// A method name formed from a literal prefix and one name, as
/// `name = 'spec_for_{fullname}'.format(**locals())` or its f-string form.
fn formed_name() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        concat!(
            r#"(?m)^[ \t]*(\w+)[ \t]*=[ \t]*(?:f['"](\w+)\{(\w+)\}['"]"#,
            r#"|['"](\w+)\{(\w+)\}['"]\.format\(\s*\*\*locals\(\s*\)\s*\))[ \t]*$"#,
        ),
    )
}

/// An attribute assignment target, which names the attribute without
/// calling it.
fn assignment_target() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"(?m)\.[ \t]*\w+[ \t]*=([^=]|$)")
}

/// Methods the import system calls on a finder or loader.
fn protocol_method() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        r"^(?:__\w+__|find_\w*|create_\w*|exec_\w*|load_\w*|get_\w*|invalidate_caches)$",
    )
}

/// The file name of a caller's frame, which a shim reads to tell a build.
fn frame_file() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r#"\bf_globals\.get\((?:'__file__'|"__file__")"#)
}

/// What a shim may do with the import system's tables: test and remove
/// entries of `sys.modules`, add or remove its own finder, and fill a
/// format string from its own locals.
fn table_use() -> &'static [(Regex, &'static str)] {
    static CELL: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    CELL.get_or_init(|| {
        [
            (r"\bin\s+sys\s*\.\s*modules\b", "in _modules_"),
            (r"\bdel\s+sys\s*\.\s*modules\s*\[", "del _modules_["),
            (r"\.format\(\s*\*\*locals\(\s*\)\s*\)", ".format()"),
            (r"\bsys\s*\.\s*meta_path\b", "_meta_path_"),
        ]
        .into_iter()
        .map(|(source, replacement)| (Regex::new(source).expect("static pattern"), replacement))
        .collect()
    })
}

/// A shim's own loader hooks, which wrap the loader it found.
fn own_loader_hook() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"\bself\.(?:exec_module|load_module)\b")
}

fn class_name() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"(?m)^[ \t]*class[ \t]+(\w+)")
}

fn attribute_by_name() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"\b(?:getattr|setattr)\(\s*([\w.]+)\s*,")
}

pub(super) fn literal(captures: &Captures) -> String {
    captures
        .get(1)
        .or_else(|| captures.get(2))
        .map_or("", |m| m.as_str())
        .to_owned()
}

pub(super) fn top(name: &str) -> &str {
    name.split('.').next().unwrap_or_default()
}

fn word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Where each whole-word `name` in `code` ends.
fn ends<'a>(code: &'a str, name: &'a str) -> impl Iterator<Item = usize> + 'a {
    code.match_indices(name).filter_map(|(at, _)| {
        let before = at.checked_sub(1).map(|index| code.as_bytes()[index]);
        let end = at + name.len();
        let after = code.as_bytes().get(end).copied();
        (!before.is_some_and(word) && !after.is_some_and(word)).then_some(end)
    })
}

/// Whether `code` names `name` as a whole word.
pub(super) fn uses(code: &str, name: &str) -> bool {
    !name.is_empty() && ends(code, name).next().is_some()
}

/// What each attribute read by name on the shim or its classes in a
/// function can call: the prefix of the method names it can form, or `None`
/// when it can form any name.
fn reach(lines: &[(&str, &str)], function: &Function, classes: &[String]) -> Vec<Option<String>> {
    let body: String = lines.iter().map(|(code, _)| format!("{code}\n")).collect();
    dispatch()
        .captures_iter(&body)
        .filter(|captures| {
            let target = &captures[1];
            matches!(target, "self" | "cls") || classes.iter().any(|name| name == target)
        })
        .map(|captures| {
            let variable = captures.get(2).map_or("", |found| found.as_str());
            prefix(variable, lines, &body, function.parameter.as_deref())
        })
        .collect()
}

/// The literal prefix of the method name `variable` holds, when the method
/// sets it once from the module name the import system called it for and
/// only reads that name.
fn prefix(
    variable: &str,
    lines: &[(&str, &str)],
    body: &str,
    parameter: Option<&str>,
) -> Option<String> {
    let parameter = parameter?;
    if variable.is_empty() || ends(body, variable).count() != 2 {
        return None;
    }
    if ends(body, parameter).any(|end| !matches!(body.as_bytes().get(end), Some(b'.' | b'}'))) {
        return None;
    }
    lines.iter().find_map(|(code, source)| {
        // The assignment must be code, not text inside a literal.
        let assigned = code.trim_start().strip_prefix(variable)?;
        if !assigned.trim_start().starts_with('=') {
            return None;
        }
        let captures = formed_name().captures(source)?;
        let (prefix, field) = match (captures.get(2), captures.get(4)) {
            (Some(prefix), _) => (prefix, captures.get(3)?),
            (_, Some(prefix)) => (prefix, captures.get(5)?),
            _ => return None,
        };
        (&captures[1] == variable && field.as_str() == parameter)
            .then(|| prefix.as_str().to_owned())
    })
}

/// Whether a read that forms names after `prefix` can call `loader`. A
/// method named for a redirected package runs only when that package is
/// imported, and the script graph refuses importing one from a site
/// directory or beside the script.
fn reachable(prefix: &Option<String>, loader: &str) -> bool {
    match prefix {
        None => true,
        Some(prefix) => loader
            .strip_prefix(prefix.as_str())
            .is_some_and(|rest| !SHIMMED.contains(&rest)),
    }
}

/// `code` without the names a definition or an attribute assignment
/// spells, so what `uses` finds in it is a use.
pub(super) fn references(code: &str) -> String {
    let code = method_definition().replace_all(code, "def _");
    assignment_target()
        .replace_all(&code, "._ =${1}")
        .into_owned()
}

/// The function each line of `code` runs in (`None` for code that runs on
/// import), and each function's name, or `None` when indentation uses tabs.
/// Only brackets continue a line; `code` has no line continuations, and a
/// replacement field's closing brace is the only bracket literal blanking
/// leaves unpaired, so depth stops at zero rather than below.
fn layout(code: &str) -> Option<(Vec<Option<usize>>, Vec<Function>)> {
    let mut owners = Vec::new();
    let mut functions = Vec::new();
    let mut scopes: Vec<(usize, Option<usize>)> = Vec::new();
    let mut depth = 0usize;
    let mut owner = None;
    for line in code.split('\n') {
        let statement = line.trim_start_matches(' ');
        if depth == 0 && !statement.trim().is_empty() {
            if statement.starts_with(|c: char| c.is_ascii_whitespace()) {
                return None;
            }
            let indent = line.len() - statement.len();
            while scopes.last().is_some_and(|(at, _)| *at >= indent) {
                scopes.pop();
            }
            owner = scopes.iter().rev().find_map(|(_, function)| *function);
            let function = definition().captures(statement).map(|captures| {
                functions.push(Function {
                    name: captures[1].to_owned(),
                    parameter: captures.get(2).map(|found| found.as_str().to_owned()),
                });
                functions.len() - 1
            });
            scopes.push((indent, function));
        }
        owners.push(owner);
        for byte in line.bytes() {
            match byte {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Some((owners, functions))
}

/// The shim in `text`, or `None` when a name in it could load code the
/// proof does not bind: a string evaluation, a file read, an `import_module`
/// inside a function of anything but a package the shim redirects, a loader
/// called on import or by the import system, or an attribute read or set by
/// name on anything but the shim's own classes and the loader it wraps. An
/// `import_module` that runs on import is bound like an import statement.
pub(super) fn shim(text: &str) -> Option<Shim> {
    if text.contains(LAZY) {
        return None;
    }
    let mut imports = Vec::new();
    let text = literal_import().replace_all(text, |captures: &Captures| {
        imports.push(Import {
            level: 0,
            module: literal(captures),
            names: Vec::new(),
        });
        "_imported_"
    });
    let mut targets = Vec::new();
    let text = literal_import_module().replace_all(&text, |captures: &Captures| {
        targets.push(literal(captures));
        LAZY
    });
    let text = frame_file().replace_all(&text, "_frame_file_(");
    let code = readable(&text)?;
    let (owners, functions) = layout(&code)?;
    let classes: Vec<String> = class_name()
        .captures_iter(&code)
        .map(|captures| captures[1].to_owned())
        .collect();
    let mut targets = targets.into_iter();
    let mut bodies = vec![String::new(); functions.len()];
    let mut lines: Vec<Vec<(&str, &str)>> = vec![Vec::new(); functions.len()];
    let mut module = String::new();
    let mut loading = vec![false; functions.len()];
    // Blanking keeps every byte's place, so `code` and `text` lines pair up.
    for ((line, source), owner) in code.split('\n').zip(text.split('\n')).zip(owners) {
        for _ in 0..line.matches(LAZY).count() {
            let target = targets.next()?;
            let Some(function) = owner else {
                imports.push(Import {
                    level: 0,
                    module: target,
                    names: Vec::new(),
                });
                continue;
            };
            let name = top(&target);
            if !SHIMMED.contains(&name) && !STANDARD_MODULES.contains(&name) {
                return None;
            }
            loading[function] = true;
        }
        if let Some(function) = owner {
            lines[function].push((line, source));
        }
        let body = owner.map_or(&mut module, |function| &mut bodies[function]);
        body.push_str(line);
        body.push('\n');
    }
    // A marker in a literal was blanked, so its target cannot be placed.
    if targets.next().is_some() {
        return None;
    }
    let bodies: Vec<String> = bodies.into_iter().map(|body| references(&body)).collect();
    let reaches: Vec<Vec<Option<String>>> = lines
        .iter()
        .zip(&functions)
        .map(|(lines, function)| reach(lines, function, &classes))
        .collect();
    loop {
        let names: Vec<&str> = functions
            .iter()
            .zip(&loading)
            .filter_map(|(function, loads)| loads.then_some(function.name.as_str()))
            .collect();
        let mut changed = false;
        for ((loads, body), reach) in loading.iter_mut().zip(&bodies).zip(&reaches) {
            let calls = names
                .iter()
                .any(|name| uses(body, name) || reach.iter().any(|prefix| reachable(prefix, name)));
            if !*loads && calls {
                *loads = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let loaders: BTreeSet<String> = functions
        .into_iter()
        .zip(loading)
        .filter_map(|(function, loads)| loads.then_some(function.name))
        .collect();
    let module = references(&module);
    if loaders
        .iter()
        .any(|name| protocol_method().is_match(name) || uses(&module, name))
    {
        return None;
    }
    let code = code.replace(LAZY, "_imported_");
    let named = references(&code);
    let mut code = code;
    for (allowed, replacement) in table_use() {
        code = allowed.replace_all(&code, *replacement).into_owned();
    }
    let code = method_definition().replace_all(&code, "def _");
    let code = own_loader_hook().replace_all(&code, "self._");
    let code = attribute_by_name().replace_all(&code, |captures: &Captures| {
        let target = &captures[1];
        if SHIM_TARGETS.contains(&target) || classes.iter().any(|name| name == target) {
            "_attr_(".to_owned()
        } else {
            captures[0].to_owned()
        }
    });
    if shim_refused().is_match(&code) || forbidden().is_match(&code) {
        return None;
    }
    imports.extend(imports_in(&code)?);
    Some(Shim {
        imports,
        loaders,
        code: named,
    })
}
