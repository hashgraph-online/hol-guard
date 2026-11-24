//! Docstrings, which document code rather than name what it opens.
//!
//! The host-reach screen reads every string literal of a program fed on
//! standard input, and of the local modules it imports, as a path the
//! program might open. Libraries document themselves in reStructuredText,
//! whose directives start with a bare `..` (`.. deprecated:: 1.0`,
//! `.. [1]`), so the screen read `..` as a path climbing out of the
//! workspace and held any probe that imported such a module; the lines
//! they start often name relative files too (`.. include:: ../README.rst`).
//! The screen skips a docstring when those lines are all that reaches: a plain
//! string (no `f` prefix, whose fields would run) that is the first
//! statement of a module or of a block, alone on its line, outside any
//! bracket, holding prose (some whitespace), whose other lines reach
//! nowhere. A docstring naming an outside path anywhere else is scanned. When the program or any module it loads can read a
//! docstring back (`__doc__`, `getdoc`, a code object's constants, an
//! attribute named at run time, the `inspect`/`ast`/`pydoc` helpers, a
//! class namespace hook), nothing is skipped.

use std::sync::LazyLock;

use regex::Regex;

/// A statement that only copies one docstring onto another
/// (`wrapper.__doc__ = wrapped.__doc__`): the value stays a docstring,
/// unless the program defines a hook that runs on assignment.
static DOC_COPY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*[\w.]+\.__doc__[ \t]*=[ \t]*[\w.]+\.__doc__[ \t]*$").unwrap()
});

/// Code that hands back a docstring's value: by name, through a code
/// object's constants, through an attribute or namespace lookup whose name
/// the scan cannot read as plain text, through the introspection helpers
/// that return docstrings or source text (`inspect`, `ast`, `pydoc`, `help`,
/// a loader's `get_source`), or through a class namespace hook
/// (`__prepare__`, `__setitem__`, a metaclass) that receives a class body's
/// docstring as a value. `getattr` is checked apart.
static READS_DOCSTRING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"__doc__|\bgetdoc\b|\bfunc_doc\b|\bco_consts\b|\b__code__\b|\bfunc_code\b",
        r"|\b__getattribute__\b|\battrgetter\b|\b__dict__\b|\b(?:vars|globals|locals)\s*\(",
        r"|\bget_docstring\b|\bgetmembers(?:_static)?\b|\bgetsource(?:lines|file)?\b",
        r"|\bgetcomments\b|\bfindsource\b|\bgetblock\b|\bpydoc\b|\brender_doc\b|\bhelp\s*\(",
        r"|\bclassify_class_attrs\b",
        r"|\bast\s*\.|\bimport\s+ast\b|\blinecache\b|\btokenize\b|\bget_source\b|\b__loader__\b",
        r"|\b__prepare__\b|\b__setitem__\b|\bmetaclass\b|\b__build_class__\b|\bnew_class\b",
    ))
    .unwrap()
});

static GETATTR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bgetattr(?:_static)?\b").unwrap());

/// The one `getattr` shape whose attribute the scan can read: a direct call
/// whose name is a single plain identifier literal (`getattr(obj, 'name')`).
/// The first argument holds no quote, so a comma or bracket inside a string
/// can never pass for the end of it.
static PLAIN_GETATTR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^\s*\((?:[^,()'"]|\([^()'"]*\))*,\s*(?:'\w+'|"\w+")\s*[,)]"#).unwrap()
});

/// Whether `code` reads a docstring back. Every mention of `getattr` counts,
/// unless it is a call with a plain identifier for the name: an alias
/// (`g = getattr`), unpacked arguments or a name built at run time could
/// all name `__doc__`.
fn reads(code: &str) -> bool {
    READS_DOCSTRING.is_match(code)
        || GETATTR
            .find_iter(code)
            .any(|found| !PLAIN_GETATTR.is_match(&code[found.end()..]))
}

/// A definition that runs user code when an attribute is assigned, which
/// would see the value of a copied docstring.
static ASSIGNMENT_HOOK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:__setattr__|__set__|setter|property)\b").unwrap());

/// Whether any of `sources` reads docstrings back as values. Copying one
/// docstring onto another is not a read, unless some source defines an
/// assignment hook that could receive the copied value.
pub(in crate::pretool) fn read_any<S: AsRef<str>>(sources: &[S]) -> bool {
    let hooked = sources
        .iter()
        .any(|source| ASSIGNMENT_HOOK.is_match(source.as_ref()));
    sources.iter().any(|source| {
        let source = source.as_ref();
        if hooked {
            reads(source)
        } else {
            reads(&DOC_COPY.replace_all(source, ""))
        }
    })
}

/// Whether `code`, a program with no other source, reads docstrings back.
#[cfg(test)]
pub(in crate::pretool) fn read(code: &str) -> bool {
    read_any(&[code])
}

/// `items` without the docstrings of `code` that `droppable` allows to go.
/// `span` gives each item's literal as a byte range of `code`, in source
/// order. The screen finds
/// literals without knowing about comments, so one may start inside a
/// comment; it is kept, and when it runs on past the comment the brackets
/// can no longer be counted, so no later string is skipped either.
pub(super) fn without<T>(
    code: &str,
    items: Vec<T>,
    span: impl Fn(&T) -> (usize, usize),
    droppable: impl Fn(&T) -> bool,
) -> Vec<T> {
    let bytes = code.as_bytes();
    let (mut at, mut depth, mut line_start, mut last) = (0usize, 0i64, true, None::<u8>);
    let mut lost = false;
    let mut kept = Vec::with_capacity(items.len());
    for item in items {
        let (start, end) = span(&item);
        lost |= start > end || end > code.len();
        if lost || start < at {
            kept.push(item);
            continue;
        }
        while at < start {
            match bytes[at] {
                b'#' => {
                    at += code[at..].find('\n').unwrap_or(code.len() - at);
                    continue;
                }
                b'\n' => line_start = last != Some(b'\\'),
                b' ' | b'\t' | b'\r' | b'\x0c' => {}
                byte => {
                    match byte {
                        b'(' | b'[' | b'{' => depth += 1,
                        b')' | b']' | b'}' => depth -= 1,
                        _ => {}
                    }
                    line_start = false;
                    last = Some(byte);
                }
            }
            at += 1;
        }
        if at > start {
            // Inside a comment.
            lost |= end > at;
            kept.push(item);
            continue;
        }
        let docstring = depth == 0
            && line_start
            && matches!(last, None | Some(b':'))
            && code[start..end]
                .trim_start_matches(['r', 'R', 'u', 'U', 'b', 'B'])
                .starts_with(['"', '\''])
            && code[start..end].contains(char::is_whitespace)
            && code[end..].split('\n').next().is_some_and(|rest| {
                let rest = rest.trim_start();
                rest.is_empty() || rest.starts_with('#')
            });
        if !docstring || !droppable(&item) {
            kept.push(item);
        }
        at = end;
        line_start = false;
        last = Some(b'"');
    }
    kept
}

/// A docstring's value without its reStructuredText explicit markup lines,
/// those whose first word is a bare `..` (`.. note:: see ../docs`,
/// `.. include:: ../README.rst`), for the path screen to read the rest.
pub(super) fn without_markup(value: &str) -> String {
    value
        .split('\n')
        .filter(|line| {
            let mut words = line.split_whitespace();
            if words.next() != Some("..") {
                return true;
            }
            match words.next() {
                Some(directive) => !directive.ends_with("::") && !directive.starts_with('['),
                None => true,
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{read, read_any, without};

    fn strings(code: &str) -> Vec<String> {
        let spans: Vec<(usize, usize)> =
            regex::Regex::new(r#"(?s)\w*(?:"""(.*?)"""|'''(.*?)'''|"[^"\n]*"|'[^'\n]*')"#)
                .unwrap()
                .find_iter(code)
                .map(|found| (found.start(), found.end()))
                .collect();
        without(code, spans, |span| *span, |_| true)
            .into_iter()
            .map(|(start, end)| code[start..end].to_owned())
            .collect()
    }

    #[test]
    fn docstrings_are_skipped() {
        for code in [
            "\"\"\"Module.\n\n.. [1] see the docs\n\"\"\"\nimport json\n",
            "def f():\n    \"\"\"Wrap it.\n\n    .. deprecated:: 11.0\n    \"\"\"\n    return 1\n",
            "class A:\n    r'''Raw ../doc'''  # note\n",
            "def f(\n    a,  # (\n):\n    '.. note'\n",
            "x = 1  # (\"a\" b)\n\ndef f():\n    '.. note'\n",
        ] {
            let found = strings(code);
            assert!(
                !found.iter().any(|found| found.contains("..")),
                "{code}: {found:?}"
            );
        }
    }

    #[test]
    fn strings_the_program_uses_are_kept() {
        for (code, kept) in [
            ("def f():\n    return '..'\n", "'..'"),
            ("x = (\n    '/etc/passwd'\n)\n", "'/etc/passwd'"),
            ("open(  # )\n    '/etc/passwd'\n)\n", "'/etc/passwd'"),
            ("if x:\n    f'{open(\"/etc/passwd\")}'\n", "\"/etc/passwd\""),
            ("def f():\n    '/etc/passwd'.join(x)\n", "'/etc/passwd'"),
            ("def f():\n    pass\n'/etc/passwd'\n", "'/etc/passwd'"),
            ("x = \\\n    '/etc/passwd'\n", "'/etc/passwd'"),
            ("d = {'k':\n    '/etc/passwd'}\n", "'/etc/passwd'"),
            ("if x: '/etc/passwd'\n", "'/etc/passwd'"),
            ("def f():\n    '../secret.txt'\n", "'../secret.txt'"),
            ("def f():\n    \"\"\"~/.ssh/id_rsa\"\"\"\n", "~/.ssh/id_rsa"),
            (
                "# say \"\"\" here\nx = 1\n\"\"\"\ndef f():\n    '/etc/passwd'\n",
                "'/etc/passwd'",
            ),
        ] {
            assert!(
                strings(code)
                    .iter()
                    .any(|found| found.contains(kept.trim_matches(['\'', '"']))),
                "{code}: {:?}",
                strings(code)
            );
        }
    }

    #[test]
    fn only_markup_lines_are_set_aside() {
        use super::without_markup;
        assert_eq!(
            without_markup(
                "Split it.\n\n    .. deprecated:: 1.0\n    .. include:: ../README.rst\n"
            ),
            "Split it.\n\n"
        );
        assert_eq!(
            without_markup("../sample file.txt\n.. note:: x"),
            "../sample file.txt"
        );
        assert_eq!(
            without_markup(".. ../sample.txt
.. note:: x"),
            ".. ../sample.txt"
        );
        assert_eq!(
            without_markup("See /etc/passwd ..\n"),
            "See /etc/passwd ..\n"
        );
    }

    #[test]
    fn copying_a_docstring_is_not_reading_it() {
        assert!(!read("wrapper.__doc__ = _wrapped.__doc__\n"));
        for code in [
            "print(open(f.__doc__).read())\n",
            "a.__doc__ = b.__doc__\nopen(a.__doc__)\n",
            "import inspect\ninspect.getdoc(f)\n",
            "print(open(f.__code__.co_consts[0]).read())\n",
            "print(open(getattr(f, '__d' 'oc__')).read())\n",
            "print(open(getattr(f, '__d' + 'oc__')).read())\n",
            "print(open(getattr(f, name)).read())\n",
            "print(open(object.__getattribute__(f, n)).read())\n",
            "print(open(operator.attrgetter(n)(f)).read())\n",
            "print(open(vars(C)[n]).read())\n",
            "a = (f, '__d' 'oc__')\nprint(open(getattr(*a)).read())\n",
            "g = getattr\nprint(open(g(f, n)).read())\n",
            "print(open(getattr(list((f,))[0], n)).read())\n",
            "import ast, inspect, m\nprint(open(ast.get_docstring(ast.parse(inspect.getsource(m)))).read())\n",
            "from inspect import getmembers\nfor _, v in getmembers(m): open(str(v))\n",
            "import pydoc, m\nprint(open(pydoc.render_doc(m).split()[3]).read())\n",
            "with redirect_stdout(b):\n    help(m)\n",
            "print(open(m.__loader__.get_source('m').split()[1]).read())\n",
            "class N(dict):\n    def __setitem__(self, k, v):\n        open(v)\nclass M(type):\n    @classmethod\n    def __prepare__(c, n, b):\n        return N()\n",
            "class C(metaclass=M):\n    \"\"\"../secret.txt documentation\"\"\"\n",
            "from inspect import classify_class_attrs\nv = [a.object for a in classify_class_attrs(C)]\n",
            "print(open(getattr(f if \", 'name')\" else f, name)).read())\n",
        ] {
            assert!(read(code), "{code}");
        }
        for code in [
            "x = getattr(obj, 'name')\n",
            "x = getattr(obj, \"name\", None)\n",
            "x = getattr(load(a, b), 'name')\n",
        ] {
            assert!(!read(code), "{code}");
        }
    }

    #[test]
    fn a_copy_into_an_assignment_hook_is_a_read() {
        let sink = "class Sink:\n    def __setattr__(self, name, value):\n        print(open(value).read())\n";
        let copy = "sink = Sink()\nsink.__doc__ = f.__doc__\n";
        assert!(!read_any(&[copy]));
        assert!(read_any(&[format!("{sink}{copy}")]));
        assert!(read_any(&[sink, copy]));
        let descriptor = "class D:\n    def __set__(self, obj, value):\n        open(value)\n";
        assert!(read_any(&[descriptor, copy]));
    }
}
