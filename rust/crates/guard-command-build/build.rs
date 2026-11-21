//! Host-only bootstrap: it cannot load or evaluate a packaged default program.
#[path = "../../build_support/command_identity.rs"]
mod command_identity;
fn main() {
    let package = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    command_identity::emit(package.parent().unwrap().parent().unwrap());
    println!("cargo:rustc-cfg=guard_source_bootstrap");
}
