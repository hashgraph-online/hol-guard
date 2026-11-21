//! A bootstrap compiler binds legacy build output to the exact raw input
//! without embedding any contribution data or granting activation authority.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{self, Read};

struct Input<R> {
    reader: R,
    hash: Sha256,
    bytes: u64,
}

impl<R: Read> Read for Input<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.reader.read(output)?;
        self.hash.update(&output[..count]);
        self.bytes += count as u64;
        Ok(count)
    }
}

pub(super) fn compile(reader: impl Read) -> Result<Value, (&'static str, String)> {
    let mut input = Input {
        reader,
        hash: Sha256::new(),
        bytes: 0,
    };
    let output = crate::native_command_program::source::compile_source_stream(&mut input).map_err(
        |error| {
            (
                error.code,
                error
                    .record
                    .map(|index| format!("/records/{index}"))
                    .unwrap_or_default(),
            )
        },
    )?;
    Ok(json!({
        "schema":"guard.command-bootstrap-build.v1", "build":output,
        "receipt":{"schema":"guard.command-source-input-receipt.v1",
        "input_sha256":hex::encode(input.hash.finalize()), "input_bytes":input.bytes}
    }))
}
