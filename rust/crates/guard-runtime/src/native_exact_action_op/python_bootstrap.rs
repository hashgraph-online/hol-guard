//! Interpreter resources and loader bytes are identity evidence, not a risk
//! verdict or execution boundary. Reuse the contained runner's static capture.
use std::path::Path;
use std::sync::atomic::AtomicBool;

use guard_contained_process::{runtime_files, runtime_resources};
use serde_json::{json, Value};

use super::super::context::Ctx;
use super::super::reasons::Proof;

const UNPROVEN: &str = "python_runtime_bootstrap_unproven";

pub(crate) fn observe(args: &[String], cwd: &str, ctx: &Ctx, executable: &Value) -> Proof<Value> {
    ctx.check()?;
    let (script, _) = super::script_argument(args).ok_or(super::MUTABLE_LAUNCHER)?;
    super::script_path(script, cwd)?;
    // Loader overrides would change the static native-loader search. Do not
    // mistake a captured default image for the one this environment loads.
    if ctx.env.iter().any(|(name, value)| {
        !value.is_empty() && (name.starts_with("LD_") || name.starts_with("DYLD_"))
    }) {
        return Err(UNPROVEN);
    }
    let text = |key: &str| executable.get(key).and_then(Value::as_str).ok_or(UNPROVEN);
    let origin = Path::new(text("launch_path")?);
    let selected = Path::new(text("path")?);
    // This root comes from the resident's enrolled authority, never from a
    // transported environment value or a caller-selected exclusion directory.
    let guard_home = ctx
        .engines
        .guard_home()
        .ok_or(UNPROVEN)?
        .canonicalize()
        .map_err(|_| UNPROVEN)?;
    let guard_home = guard_home.as_path();
    let cancel = AtomicBool::new(false);
    let resources =
        runtime_resources::python_identity(origin, selected, guard_home, ctx.deadline, &cancel)
            .map_err(|_| UNPROVEN)?;
    if resources.python_version.is_none() {
        return Err(UNPROVEN);
    }
    let native = |data: &[u8]| {
        [
            b"\x7fELF".as_slice(),
            b"MZ",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
            b"\xca\xfe\xba\xbf",
        ]
        .iter()
        .any(|magic| data.starts_with(magic))
    };
    let libraries: Vec<_> = resources
        .files
        .iter()
        .filter(|file| native(&file.bytes))
        .map(|file| (file.source.clone(), file.bytes.as_slice()))
        .collect();
    let images = runtime_files::capture_with_libraries(
        selected,
        text("sha256")?,
        &libraries,
        guard_home,
        ctx.deadline,
        &cancel,
    )
    .map_err(|_| UNPROVEN)?;
    let stdlib = resources.standard_library.as_ref().ok_or(UNPROVEN)?;
    let version = resources.python_version.as_ref().ok_or(UNPROVEN)?;
    let primary: Vec<_> = images
        .files
        .iter()
        .filter(|file| {
            file.names
                .iter()
                .any(|name| name.starts_with("libpython") || name == "Python")
        })
        .collect();
    let shared = !primary.is_empty();
    let origins: Vec<_> = if shared {
        primary.iter().map(|file| file.source.as_path()).collect()
    } else {
        vec![selected]
    };
    for image in origins {
        let library =
            super::startup::runtime_native_library(image.to_str().ok_or(UNPROVEN)?, version)
                .map_err(|_| UNPROVEN)?;
        // A copied distribution can have both its own libpython/stdlib and
        // conflicting venv metadata. Bind the actual loader's installation;
        // do not certify a different tree merely because metadata names it.
        if library
            .as_ref()
            .is_some_and(|path| Path::new(path) != stdlib)
            || (shared && library.is_none())
        {
            return Err(UNPROVEN);
        }
    }
    let destination = std::path::PathBuf::from(format!("python/lib/python{version}"));
    let sources: Vec<_> = resources
        .files
        .iter()
        .filter(|file| {
            file.destination
                .extension()
                .is_some_and(|extension| extension == "py")
        })
        .map(|file| {
            let relative = file
                .destination
                .strip_prefix(&destination)
                .map_err(|_| UNPROVEN)?;
            stdlib
                .join(relative)
                .to_str()
                .map(str::to_owned)
                .ok_or(UNPROVEN)
        })
        .collect::<Proof<_>>()?;
    let mut code = super::python_script(args, cwd, ctx, executable, &sources)?;
    resources.verify().map_err(|_| UNPROVEN)?;
    for binding in &images.bindings {
        ctx.check()?;
        binding.verify().map_err(|_| UNPROVEN)?;
    }
    let files: Vec<_> = resources
        .files
        .iter()
        .map(|file| {
            json!({
                "source":file.source,"destination":file.destination,"sha256":file.digest,
            })
        })
        .collect();
    let libraries: Vec<_> = images
        .files
        .iter()
        .map(|file| {
            json!({
                "source":file.source,"names":file.names,"sha256":file.digest,
            })
        })
        .collect();
    code["bootstrap"] = json!({
        "version":resources.python_version,"configuration":resources.configuration,
        "files":files,"directories":resources.directories,
        "native_digest":images.digest,"libraries":libraries,
        "native_bytes":images.total_bytes,"resource_bytes":resources.total_bytes,
    });
    ctx.check()?;
    Ok(code)
}
