//! The modules a `python3 -c` filter may import, and the names that would
//! shadow the standard library from the working directory.

/// Each importable module with the attributes the filter may name on it.
/// Every list is explicit and names no module object: `fractions` imports
/// `sys`, so a wildcard would let `fractions.sys` reach the interpreter.
#[rustfmt::skip]
const MODULES: &[(&str, &[&str])] = &[
    ("base64", &[
        "b16decode", "b16encode", "b32decode", "b32encode", "b64decode", "b64encode", "decodebytes",
        "encodebytes", "standard_b64decode", "standard_b64encode", "urlsafe_b64decode",
        "urlsafe_b64encode",
    ]),
    ("bisect", &["bisect", "bisect_left", "bisect_right", "insort", "insort_left", "insort_right"]),
    ("collections", &["ChainMap", "Counter", "OrderedDict", "defaultdict", "deque", "namedtuple"]),
    ("csv", &[
        "DictReader", "DictWriter", "Error", "QUOTE_ALL", "QUOTE_MINIMAL", "QUOTE_NONE",
        "QUOTE_NONNUMERIC", "excel", "excel_tab", "reader", "writer",
    ]),
    ("datetime", &[
        "MAXYEAR", "MINYEAR", "UTC", "date", "datetime", "time", "timedelta", "timezone",
    ]),
    ("decimal", &[
        "Context", "Decimal", "DivisionByZero", "Inexact", "InvalidOperation", "Overflow",
        "ROUND_05UP", "ROUND_CEILING", "ROUND_DOWN", "ROUND_FLOOR", "ROUND_HALF_DOWN",
        "ROUND_HALF_EVEN", "ROUND_HALF_UP", "ROUND_UP", "Rounded", "getcontext", "localcontext",
    ]),
    ("difflib", &[
        "Differ", "HtmlDiff", "SequenceMatcher", "context_diff", "diff_bytes", "get_close_matches",
        "ndiff", "restore", "unified_diff",
    ]),
    ("fractions", &["Fraction"]),
    ("functools", &[
        "cache", "cmp_to_key", "lru_cache", "partial", "reduce", "total_ordering", "wraps",
    ]),
    ("hashlib", &[
        "blake2b", "blake2s", "md5", "new", "sha1", "sha224", "sha256", "sha384", "sha3_256",
        "sha3_512", "sha512",
    ]),
    ("heapq", &[
        "heapify", "heappop", "heappush", "heappushpop", "heapreplace", "merge", "nlargest",
        "nsmallest",
    ]),
    ("html", &["escape", "unescape"]),
    ("itertools", &[
        "accumulate", "batched", "chain", "combinations", "combinations_with_replacement",
        "compress", "count", "cycle", "dropwhile", "filterfalse", "groupby", "islice", "pairwise",
        "permutations", "product", "repeat", "starmap", "takewhile", "tee", "zip_longest",
    ]),
    ("json", &["JSONDecodeError", "dump", "dumps", "load", "loads"]),
    ("math", &[
        "acos", "acosh", "asin", "asinh", "atan", "atan2", "atanh", "cbrt", "ceil", "comb",
        "copysign", "cos", "cosh", "degrees", "dist", "e", "erf", "erfc", "exp", "exp2", "expm1",
        "fabs", "factorial", "floor", "fma", "fmod", "frexp", "fsum", "gamma", "gcd", "hypot", "inf",
        "isclose", "isfinite", "isinf", "isnan", "isqrt", "lcm", "ldexp", "lgamma", "log", "log10",
        "log1p", "log2", "modf", "nan", "nextafter", "perm", "pi", "pow", "prod", "radians",
        "remainder", "sin", "sinh", "sqrt", "sumprod", "tan", "tanh", "tau", "trunc", "ulp",
    ]),
    ("operator", &[
        "abs", "add", "and_", "contains", "countOf", "eq", "floordiv", "ge", "gt", "indexOf",
        "itemgetter", "le", "lt", "mod", "mul", "ne", "neg", "not_", "or_", "pos", "sub", "truediv",
        "truth", "xor",
    ]),
    ("pprint", &["PrettyPrinter", "pformat", "pp", "pprint"]),
    ("random", &[
        "Random", "choice", "choices", "gauss", "randint", "random", "randrange", "sample", "seed",
        "shuffle", "uniform",
    ]),
    ("re", &[
        "A", "ASCII", "DOTALL", "I", "IGNORECASE", "M", "MULTILINE", "S", "VERBOSE", "X", "compile",
        "error", "escape", "findall", "finditer", "flags", "fullmatch", "match", "search", "split",
        "sub", "subn",
    ]),
    ("shlex", &["join", "quote", "split"]),
    ("statistics", &[
        "NormalDist", "StatisticsError", "correlation", "covariance", "fmean", "geometric_mean",
        "harmonic_mean", "linear_regression", "mean", "median", "median_grouped", "median_high",
        "median_low", "mode", "multimode", "pstdev", "pvariance", "quantiles", "stdev", "variance",
    ]),
    ("string", &[
        "ascii_letters", "ascii_lowercase", "ascii_uppercase", "capwords", "digits", "hexdigits",
        "octdigits", "printable", "punctuation", "whitespace",
    ]),
    ("sys", &[
        "argv", "exit", "maxsize", "platform", "stderr", "stdin", "stdout", "version",
        "version_info",
    ]),
    ("textwrap", &["TextWrapper", "dedent", "fill", "indent", "shorten", "wrap"]),
    ("time", &[
        "asctime", "ctime", "gmtime", "localtime", "mktime", "monotonic", "perf_counter",
        "strftime", "strptime", "time", "time_ns",
    ]),
    ("unicodedata", &[
        "bidirectional", "category", "combining", "decimal", "decomposition", "digit",
        "east_asian_width", "is_normalized", "lookup", "mirrored", "name", "normalize", "numeric",
        "unidata_version",
    ]),
];

/// Whether the filter may import `module`.
pub(super) fn importable(module: &str) -> bool {
    MODULES.iter().any(|(name, _)| *name == module)
}

/// Whether the filter may name `attribute` on `module`.
pub(super) fn attribute_allowed(module: &str, attribute: &str) -> bool {
    MODULES
        .iter()
        .find(|(name, _)| *name == module)
        .is_some_and(|(_, attributes)| {
            !attribute.starts_with('_') && attributes.contains(&attribute)
        })
}

/// Top-level standard library modules, the startup hooks, and modules that
/// recent releases removed. A file or package of one of these names in the
/// working directory would run in place of the real module the moment the
/// interpreter or an allowed module imports it, an error traceback included.
#[rustfmt::skip]
const STANDARD_LIBRARY: &[&str] = &[
    "abc", "annotationlib", "antigravity", "argparse", "array", "ast", "asynchat", "asyncio",
    "asyncore", "atexit", "base64", "bdb", "binascii", "bisect", "builtins", "bz2", "cProfile",
    "calendar", "cgi", "cgitb", "chunk", "cmath", "cmd", "code", "codecs", "codeop", "collections",
    "colorsys", "compileall", "compression", "concurrent", "configparser", "contextlib",
    "contextvars", "copy", "copyreg", "crypt", "csv", "ctypes", "curses", "dataclasses", "datetime",
    "dbm", "decimal", "difflib", "dis", "distutils", "doctest", "email", "encodings", "ensurepip",
    "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput", "fnmatch", "fractions",
    "ftplib", "functools", "gc", "genericpath", "getopt", "getpass", "gettext", "glob", "graphlib",
    "grp", "gzip", "hashlib", "heapq", "hmac", "html", "http", "idlelib", "imaplib", "imghdr",
    "imp", "importlib", "inspect", "io", "ipaddress", "itertools", "json", "keyword", "lib2to3",
    "linecache", "locale", "logging", "lzma", "mailbox", "mailcap", "marshal", "math", "mimetypes",
    "mmap", "modulefinder", "msilib", "msvcrt", "multiprocessing", "netrc", "nis", "nntplib", "nt",
    "ntpath", "nturl2path", "numbers", "opcode", "operator", "optparse", "os", "ossaudiodev",
    "pathlib", "pdb", "pickle", "pickletools", "pipes", "pkgutil", "platform", "plistlib", "poplib",
    "posix", "posixpath", "pprint", "profile", "pstats", "pty", "pwd", "py_compile", "pyclbr",
    "pydoc", "pydoc_data", "pyexpat", "queue", "quopri", "random", "re", "readline", "reprlib",
    "resource", "rlcompleter", "runpy", "sched", "secrets", "select", "selectors", "shelve",
    "shlex", "shutil", "signal", "site", "sitecustomize", "smtpd", "smtplib", "sndhdr", "socket",
    "socketserver", "spwd", "sqlite3", "sre_compile", "sre_constants", "sre_parse", "ssl", "stat",
    "statistics", "string", "stringprep", "struct", "subprocess", "sunau", "symtable", "sys",
    "sysconfig", "syslog", "tabnanny", "tarfile", "telnetlib", "tempfile", "termios", "textwrap",
    "this", "threading", "time", "timeit", "tkinter", "token", "tokenize", "tomllib", "trace",
    "traceback", "tracemalloc", "tty", "turtle", "turtledemo", "types", "typing", "unicodedata",
    "unittest", "urllib", "usercustomize", "uu", "uuid", "venv", "warnings", "wave", "weakref",
    "webbrowser", "winreg", "winsound", "wsgiref", "xdrlib", "xml", "xmlrpc", "zipapp", "zipfile",
    "zipimport", "zlib", "zoneinfo",
];

/// Whether a module of this name, found first on the path, could replace one
/// the interpreter loads. Private modules such as `_colorize` count too.
pub(super) fn shadows_standard_library(stem: &str) -> bool {
    stem.starts_with('_')
        || STANDARD_LIBRARY
            .iter()
            .any(|name| name.eq_ignore_ascii_case(stem))
}

/// `PYTHON*` variables that only change output buffering, text encoding,
/// hash seeding or diagnostics, or that narrow the module path further.
const HARMLESS_ENVIRONMENT: &[&str] = &[
    "PYTHONCOERCECLOCALE",
    "PYTHONDEVMODE",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONFAULTHANDLER",
    "PYTHONHASHSEED",
    "PYTHONINTMAXSTRDIGITS",
    "PYTHONIOENCODING",
    "PYTHONNOUSERSITE",
    "PYTHONSAFEPATH",
    "PYTHONUNBUFFERED",
    "PYTHONUTF8",
];

/// Whether an inherited variable can change what the interpreter loads.
pub(super) fn steering_variable(name: &str) -> bool {
    name.get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("PYTHON"))
        && !HARMLESS_ENVIRONMENT
            .iter()
            .any(|harmless| harmless.eq_ignore_ascii_case(name))
}
