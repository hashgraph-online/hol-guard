//! `runner_authority` kind `opencode_plugin_render`: the source of the
//! managed OpenCode pretool plugin (`hol-guard-pretool.ts`).
//!
//! Python attests the Guard CLI and passes what it found; this kind owns the
//! plugin template, its constants and the Python bootstrap the plugin falls
//! back to. Each placeholder is replaced in the order `pretool_plugin_source`
//! replaced it, with the value spelled the way `json.dumps` spells it, so a
//! reinstall writes the same bytes and the update check compares equal.

use serde_json::{Map, Value};

use super::bounded_hook_bridge::BRIDGE_COMMAND;
use super::pyjson::{float_repr, parse_marking_lone_surrogates, PyVal, LONE_SURROGATE_MARK};
use super::runner_authority_op::{KindResult, ERR_INVALID};

// The plugin template is split in two; only the first part carries placeholders.
const TEMPLATE: &str = include_str!("opencode_plugin_render.ts.txt");
const TEMPLATE_HOOK: &str = include_str!("opencode_plugin_render_hook.ts.txt");
const HOOK_ARGV_ENV: &str = "HOL_GUARD_HOOK_ARGV";
const HOOK_TIMEOUT_SECONDS: u32 = 25;
const INTERCEPT_TOOLS: &[&str] = &[
    "bash",
    "ctx_shell",
    "shell",
    "sh",
    "zsh",
    "terminal",
    "oc_bash",
];
const INHERIT_ENV_KEYS: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "SYSTEMROOT",
    "HOL_GUARD_NATIVE",
    "HOL_GUARD_NATIVE_BINARY",
];
const HOOK_ENV: &[(&str, &str)] = &[
    ("PYTHONDONTWRITEBYTECODE", "1"),
    ("PYTHONIOENCODING", "utf-8"),
    ("PYTHONNOUSERSITE", "1"),
    ("PYTHONSAFEPATH", "1"),
];
const STAT_FIELDS: &[(&str, &str)] = &[
    ("device", "device"),
    ("inode", "inode"),
    ("mode", "mode"),
    ("size", "size"),
    ("mtime_ns", "mtimeNs"),
];

/// `{"guard_home", "python", "frozen", "native_bridge_argv", "import_roots",
/// "taskkill_path"}` to `{"source": <plugin text>}`.
pub(crate) fn render(args: &Value) -> KindResult {
    let fields = args
        .as_object()
        .filter(|fields| fields.len() == 6)
        .ok_or(ERR_INVALID)?;
    let guard_home = text(fields, "guard_home")?;
    let python = identity(fields.get("python").ok_or(ERR_INVALID)?)?;
    let frozen = fields
        .get("frozen")
        .and_then(Value::as_bool)
        .ok_or(ERR_INVALID)?;
    let bridge = native_bridge(fields.get("native_bridge_argv").ok_or(ERR_INVALID)?)?;
    let import_roots = texts(fields.get("import_roots").ok_or(ERR_INVALID)?)?;
    let taskkill = match fields.get("taskkill_path").ok_or(ERR_INVALID)? {
        Value::Null => PyVal::Null,
        Value::String(path) => PyVal::Str(path.clone()),
        _ => return Err(ERR_INVALID),
    };
    let strings = |items: &[&str]| {
        PyVal::List(
            items
                .iter()
                .map(|item| PyVal::Str((*item).to_owned()))
                .collect(),
        )
    };
    let env = PyVal::Dict(
        HOOK_ENV
            .iter()
            .map(|(key, value)| ((*key).to_owned(), str_val(value)))
            .collect(),
    );
    let replacements = [
        ("__GUARD_HOME__", str_val(guard_home)),
        ("__GUARD_PYTHON__", python),
        ("__GUARD_FROZEN__", PyVal::Bool(frozen)),
        ("__GUARD_NATIVE_BRIDGE__", bridge),
        (
            "__GUARD_HOOK_LAUNCHER__",
            PyVal::Str(hook_launcher_code(&import_roots)),
        ),
        ("__GUARD_HOOK_ENV__", env),
        ("__GUARD_INHERIT_ENV_KEYS__", strings(INHERIT_ENV_KEYS)),
        ("__GUARD_TASKKILL_PATH__", taskkill),
        ("__INTERCEPT_TOOLS__", strings(INTERCEPT_TOOLS)),
    ];
    let mut source = TEMPLATE.to_owned();
    for (placeholder, value) in replacements {
        source = source.replace(placeholder, &dumps(&value));
    }
    source.push_str(TEMPLATE_HOOK);
    Ok(serde_json::json!({ "source": source }))
}

fn str_val(value: &str) -> PyVal {
    PyVal::Str(value.to_owned())
}

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    fields.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn texts(value: &Value) -> Result<Vec<String>, &'static str> {
    value
        .as_array()
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or(ERR_INVALID))
        .collect()
}

/// `str(int)` of one `HookPythonFileMetadata` field; the request keeps the
/// integer's digits, so a value past 64 bits reads as Python wrote it.
fn integer(value: &Value) -> Result<PyVal, &'static str> {
    let Value::Number(number) = value else {
        return Err(ERR_INVALID);
    };
    let digits = number.to_string();
    let magnitude = digits.strip_prefix('-').unwrap_or(&digits);
    if magnitude.is_empty() || !magnitude.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ERR_INVALID);
    }
    Ok(PyVal::Str(digits))
}

/// `_metadata_payload`: every stat field as its decimal text.
fn metadata(value: &Value) -> Result<PyVal, &'static str> {
    let fields = value
        .as_object()
        .filter(|fields| fields.len() == STAT_FIELDS.len())
        .ok_or(ERR_INVALID)?;
    STAT_FIELDS
        .iter()
        .map(|(source, target)| {
            let field = fields.get(*source).ok_or(ERR_INVALID)?;
            Ok(((*target).to_owned(), integer(field)?))
        })
        .collect::<Result<Vec<_>, &'static str>>()
        .map(PyVal::Dict)
}

/// `_python_identity_payload` from the attestation's executable identity.
fn identity(value: &Value) -> Result<PyVal, &'static str> {
    let fields = value
        .as_object()
        .filter(|fields| fields.len() == 7)
        .ok_or(ERR_INVALID)?;
    let link_target = match fields.get("invocation_link_target").ok_or(ERR_INVALID)? {
        Value::Null => PyVal::Null,
        Value::String(target) => str_val(target),
        _ => return Err(ERR_INVALID),
    };
    let field = |key: &str| text(fields, key).map(str_val);
    let stat = |key: &str| metadata(fields.get(key).ok_or(ERR_INVALID)?);
    Ok(PyVal::Dict(vec![
        ("invocationPath".to_owned(), field("invocation_path")?),
        ("invocationType".to_owned(), field("invocation_type")?),
        ("invocationLinkTarget".to_owned(), link_target),
        ("invocationStat".to_owned(), stat("invocation_stat")?),
        ("targetPath".to_owned(), field("target_path")?),
        ("targetStat".to_owned(), stat("target_stat")?),
        ("targetSha256".to_owned(), field("target_sha256")?),
    ]))
}

/// `_native_bridge_payload`: the bounded native hook argv the plugin starts
/// first, or `None` to keep the Python launcher.
fn native_bridge(value: &Value) -> Result<PyVal, &'static str> {
    if value.is_null() {
        return Ok(PyVal::Null);
    }
    let argv = texts(value)?;
    if argv.len() != 7 || argv[1] != BRIDGE_COMMAND {
        return Ok(PyVal::Null);
    }
    let config = parse_marking_lone_surrogates(&argv[6]).map_err(|_| ERR_INVALID)?;
    if carries_mark(&config) {
        return Err(ERR_INVALID);
    }
    Ok(PyVal::Dict(vec![
        ("runtimePath".to_owned(), str_val(&argv[0])),
        ("bootstrap".to_owned(), str_val(&argv[5])),
        ("config".to_owned(), config),
    ]))
}

/// A lone surrogate has no Rust `str` form to write back. The request cannot
/// carry one in the Guard home or interpreter paths either, so the bridge
/// config refuses it the same way.
fn carries_mark(value: &PyVal) -> bool {
    match value {
        PyVal::Str(text) => text.contains(LONE_SURROGATE_MARK),
        PyVal::List(items) => items.iter().any(carries_mark),
        PyVal::Dict(entries) => entries
            .iter()
            .any(|(key, item)| key.contains(LONE_SURROGATE_MARK) || carries_mark(item)),
        _ => false,
    }
}

/// `_pretool_hook_launcher_code(import_roots=...)`: the `python -c` program
/// the plugin runs when the native bridge is unavailable.
fn hook_launcher_code(import_roots: &[String]) -> String {
    let trusted = PyVal::List(
        import_roots
            .iter()
            .map(|root| PyVal::Str(root.clone()))
            .collect(),
    );
    [
        "import json,os,sys;".to_owned(),
        format!("trusted={};", dumps(&trusted)),
        "sys.path[:0]=trusted;".to_owned(),
        "from codex_plugin_scanner.guard.codex_hook_windows_job import ".to_owned(),
        "assign_current_process_to_windows_hook_job;".to_owned(),
        "_windows_job=assign_current_process_to_windows_hook_job() if os.name=='nt' else None;"
            .to_owned(),
        "sys.stderr.write('HOL_GUARD_WINDOWS_JOB_CONTAINED\\n') if _windows_job is not None else None;"
            .to_owned(),
        "sys.stderr.flush() if _windows_job is not None else None;".to_owned(),
        "from pathlib import Path;".to_owned(),
        "import codex_plugin_scanner;".to_owned(),
        "from codex_plugin_scanner.guard.hook_execution_environment import stamp_hook_input_text;"
            .to_owned(),
        "from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import run_bounded_cli_hook;"
            .to_owned(),
        format!("argv=json.loads(os.environ['{HOOK_ARGV_ENV}']);"),
        "guard_index=argv.index('--guard-home');".to_owned(),
        "guard_home=argv[guard_index+1];".to_owned(),
        "package_root=Path(codex_plugin_scanner.__file__).resolve().parent.parent;".to_owned(),
        "config={'python_executable':sys.executable,'package_root':str(package_root),".to_owned(),
        format!(
            "'guard_home':guard_home,'cli_args':argv,'harness':'opencode','timeout_seconds':{HOOK_TIMEOUT_SECONDS}}};"
        ),
        "raise SystemExit(run_bounded_cli_hook(config,input_text=stamp_hook_input_text(sys.stdin.read(1000001))))"
            .to_owned(),
    ]
    .concat()
}

/// `json.dumps(value)`: insertion order, `", "` and `": "`, ASCII only.
pub(crate) fn dumps(value: &PyVal) -> String {
    let mut out = String::new();
    write(value, &mut out);
    out
}

fn write(value: &PyVal, out: &mut String) {
    match value {
        PyVal::Null => out.push_str("null"),
        PyVal::Bool(true) => out.push_str("true"),
        PyVal::Bool(false) => out.push_str("false"),
        PyVal::Int(digits) => out.push_str(digits),
        PyVal::Float(number) if number.is_nan() => out.push_str("NaN"),
        PyVal::Float(number) if number.is_infinite() => out.push_str(if *number > 0.0 {
            "Infinity"
        } else {
            "-Infinity"
        }),
        PyVal::Float(number) => out.push_str(&float_repr(*number)),
        PyVal::Str(text) => write_string(text, out),
        PyVal::List(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write(item, out);
            }
            out.push(']');
        }
        PyVal::Dict(entries) => {
            out.push('{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_string(key, out);
                out.push_str(": ");
                write(item, out);
            }
            out.push('}');
        }
    }
}

/// `json.encoder.py_encode_basestring_ascii`.
fn write_string(value: &str, out: &mut String) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(character),
            _ => {
                let code = character as u32;
                if code <= 0xffff {
                    out.push_str(&format!("\\u{code:04x}"));
                } else {
                    let adjusted = code - 0x1_0000;
                    out.push_str(&format!("\\u{:04x}", 0xd800 + (adjusted >> 10)));
                    out.push_str(&format!("\\u{:04x}", 0xdc00 + (adjusted & 0x3ff)));
                }
            }
        }
    }
    out.push('"');
}
