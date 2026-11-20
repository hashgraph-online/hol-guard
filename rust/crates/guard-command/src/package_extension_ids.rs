//! The package-firewall extension identifiers.
//!
//! These name which package ecosystem a command ran, not a risk the run
//! carries. They sit at the crate's base so both the command-shape proofs and
//! the hook responses that read a decision's permissions can name them without
//! depending on each other.

const NODE_PACKAGE_EXTENSION: &str = "command.package.node";
const PYTHON_PACKAGE_EXTENSION: &str = "command.package.python";
const GO_PACKAGE_EXTENSION: &str = "command.package.go";
const RUST_PACKAGE_EXTENSION: &str = "command.package.rust";
const PHP_PACKAGE_EXTENSION: &str = "command.package.php";
const RUBY_PACKAGE_EXTENSION: &str = "command.package.ruby";
const JVM_PACKAGE_EXTENSION: &str = "command.package.jvm";

/// The package-firewall permissions that mark a manager's use. They record
/// which ecosystem ran, not a risk the run carries, so a local verb below one
/// of them is still ordinary workspace work.
pub(crate) const PACKAGE_EXTENSIONS: &[&str] = &[
    NODE_PACKAGE_EXTENSION,
    PYTHON_PACKAGE_EXTENSION,
    GO_PACKAGE_EXTENSION,
    RUST_PACKAGE_EXTENSION,
    PHP_PACKAGE_EXTENSION,
    RUBY_PACKAGE_EXTENSION,
    JVM_PACKAGE_EXTENSION,
];
