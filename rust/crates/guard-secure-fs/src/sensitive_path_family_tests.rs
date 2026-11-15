use super::sensitive_path_family;
use std::path::Path;

/// Wrangler keeps a worker's local secrets in `.dev.vars`, with one
/// `.dev.vars.<environment>` file per environment.
#[test]
fn wrangler_dev_vars_files_are_sensitive() {
    for path in [
        "workers/api/.dev.vars",
        ".dev.vars.staging",
        "workers\\api\\.DEV.VARS",
    ] {
        assert_eq!(
            sensitive_path_family(Path::new(path)),
            Some(("Wrangler local secrets file", "high")),
            "{path}"
        );
    }
    for path in [
        "workers/api/dev.vars",
        "workers/api/.dev.varsity",
        "src/vars.ts",
    ] {
        assert_eq!(sensitive_path_family(Path::new(path)), None, "{path}");
    }
}
