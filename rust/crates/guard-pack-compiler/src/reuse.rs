//! Offline file transport for a root authenticated by the publication caller.
use guard_command_build::native_command_program::source::{
    compile_pack_stream_reusing, PackReleaseReuse,
};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

fn bounded_file(path: &Path) -> Result<Vec<u8>, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "command_pack_reuse_file_missing")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 65536 {
        return Err("command_pack_reuse_file_invalid");
    }
    let file = fs::File::open(path).map_err(|_| "command_pack_reuse_file_missing")?;
    let metadata = file
        .metadata()
        .map_err(|_| "command_pack_reuse_file_invalid")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 65536 {
        return Err("command_pack_reuse_file_invalid");
    }
    let mut bytes = Vec::new();
    file.take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "command_pack_reuse_file_invalid")?;
    if bytes.len() != metadata.len() as usize {
        return Err("command_pack_reuse_file_invalid");
    }
    Ok(bytes)
}

pub fn run(directory: &Path, root_digest: &str) -> Result<(), &'static str> {
    // Never discover authority from a cache. This digest is a separate argument
    // provided only after the publication caller verifies Sigstore provenance.
    if directory
        .ancestors()
        .any(|path| fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()))
        || fs::symlink_metadata(directory.join("objects"))
            .map_err(|_| "command_pack_reuse_file_missing")?
            .file_type()
            .is_symlink()
    {
        return Err("command_pack_reuse_file_invalid");
    }
    let root = bounded_file(&directory.join("release.json"))?;
    let mut reuse = PackReleaseReuse::from_bytes(&root, root_digest, |id: &str| {
        if id.len() != 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("command_pack_reuse_file_invalid");
        }
        bounded_file(&directory.join("objects").join(format!("{id}.json")))
    })?;
    let mut output = std::io::stdout().lock();
    let (root, stats) =
        compile_pack_stream_reusing(std::io::stdin().lock(), &mut output, &mut reuse)?;
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
    Ok(())
}
