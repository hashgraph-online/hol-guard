//! Standalone offline compiler front end. The operations live in
//! `guard_command::source_cli` so the runtime binary can host them too.

fn main() {
    std::process::exit(guard_command::source_cli::main(
        std::env::args().skip(1).collect(),
    ));
}
