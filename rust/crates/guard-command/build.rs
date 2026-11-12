//! Emit the shared implementation identity; catalog generation lives in
//! `guard-command-catalog-data` so crate-local edits stay off that path.
#[path = "../../build_support/command_identity.rs"]
mod command_identity;
fn main() {
    let package = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    command_identity::emit(package.parent().unwrap().parent().unwrap());
}
