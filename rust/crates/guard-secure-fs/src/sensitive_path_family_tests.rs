use super::{dotenv_template_basename, sensitive_path_family};
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

/// A committed dotenv template carries one of the suffixes a repository uses
/// to document the variables a project reads. The family screen still answers
/// for every one of them: the name alone proves nothing, and the caller that
/// reads past it does so on a tracked, secret-free file.
#[test]
fn template_suffixes_are_named_without_relaxing_the_family() {
    for path in [
        "services/billing-api/.env.example",
        ".env.sample",
        "web-console/.env.template",
        "packages/app/.env.dist",
        "atlas-tools/.env.defaults",
        "packages/app/.ENV.Example",
    ] {
        let basename = Path::new(path).file_name().unwrap().to_str().unwrap();
        assert!(dotenv_template_basename(basename), "{path}");
        assert_eq!(
            sensitive_path_family(Path::new(path)),
            Some(("local .env file", "critical")),
            "{path}"
        );
    }
}

/// The local dotenv file, and every variant naming an environment, are not
/// templates. A suffix that merely begins with a template word is the local
/// file.
#[test]
fn the_local_dotenv_file_is_not_a_template() {
    for path in [
        "services/billing-api/.env",
        ".env.local",
        "web-console/.env.production",
        "packages/app/.env.development.local",
        "packages/app/.env.examples",
        "packages/app/.env.example.key",
    ] {
        let basename = Path::new(path).file_name().unwrap().to_str().unwrap();
        assert!(!dotenv_template_basename(basename), "{path}");
        assert!(sensitive_path_family(Path::new(path)).is_some(), "{path}");
    }
}
