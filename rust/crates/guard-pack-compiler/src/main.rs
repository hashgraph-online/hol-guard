//! Maintainer-only source compiler without an embedded contribution catalog.
//! Input is explicit bounded source records; output has no activation authority.

use std::io::{Read, Write};
mod reuse;

fn session() -> Result<(), &'static str> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut compiler = guard_command_build::native_command_program::source::PackCompiler::default();
    loop {
        let mut length = [0; 8];
        match input.read(&mut length[..1]) {
            Ok(0) => return Ok(()),
            Ok(_) => (),
            Err(_) => return Err("command_pack_session_read_failed"),
        }
        input
            .read_exact(&mut length[1..])
            .map_err(|_| "command_pack_session_truncated")?;
        let length = u64::from_be_bytes(length);
        if length == 0 {
            return Err("command_pack_session_length_invalid");
        }
        // The session never materializes an aggregate request. The compiler
        // validates each original source record at its unchanged byte limit.
        let mut request = input.by_ref().take(length);
        let (root, stats) = compiler.compile(&mut request, &mut output)?;
        if request.limit() != 0 {
            return Err("command_pack_session_truncated");
        }
        serde_json::to_writer(
            &mut output,
            &serde_json::json!({"kind":"compilation", "stats":stats}),
        )
        .map_err(|_| "command_pack_output_failed")?;
        output
            .write_all(b"\n")
            .map_err(|_| "command_pack_output_failed")?;
        serde_json::to_writer(&mut output, &root).map_err(|_| "command_pack_output_failed")?;
        output
            .write_all(b"\n")
            .map_err(|_| "command_pack_output_failed")?;
        output.flush().map_err(|_| "command_pack_output_failed")?;
    }
}

fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if let [operation, directory, digest] = arguments.as_slice() {
        if operation == "compile-packs-reuse" {
            if let Err(code) = reuse::run(std::path::Path::new(directory), digest) {
                println!("{}", serde_json::json!({"ok":false,"code":code}));
                std::process::exit(2);
            }
            return;
        }
    }
    if arguments == ["compile-packs-session"] {
        if let Err(code) = session() {
            println!("{}", serde_json::json!({"ok":false,"code":code}));
            std::process::exit(2);
        }
        return;
    }
    // `bundle-metadata` only checks the JSON it is given (release defaults for
    // policy delivery); it never reads or evaluates a packaged program.
    if !matches!(arguments.as_slice(), [operation] if matches!(operation.as_str(), "compiler-info" | "compile-bootstrap-stream" | "compile-packs" | "schema" | "descriptor-schema" | "bundle-metadata"))
    {
        println!(
            "{}",
            serde_json::json!({"ok":false, "code":"pack_compiler_operation_unsupported"})
        );
        std::process::exit(2);
    }
    std::process::exit(guard_command_build::source_cli::main(arguments));
}
