use super::{bytes, invalid, string, u32le, Import};
use std::io;
use std::path::{Path, PathBuf};

pub(super) fn mach(data: &[u8], library: &Path, executable: &Path) -> io::Result<Vec<Import>> {
    if !data.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]) {
        return Err(invalid());
    }
    let count = u32le(data, 16)? as usize;
    if count > 4096 {
        return Err(invalid());
    }
    let end = 32 + u32le(data, 20)? as usize;
    bytes(data, 32, end.checked_sub(32).ok_or_else(invalid)?)?;
    let mut at = 32;
    let mut names = Vec::new();
    let mut rpaths = Vec::new();
    for _ in 0..count {
        let command = u32le(data, at)?;
        let size = u32le(data, at + 4)? as usize;
        if size < 8 || at + size > end {
            return Err(invalid());
        }
        if [0x0c, 0x8000_0018, 0x8000_001f, 0x8000_0023].contains(&command) {
            let name = string(data, at + u32le(data, at + 8)? as usize, at + size)?;
            names.push((name, command == 0x8000_0018));
        }
        if command == 0x8000_001c {
            rpaths.push(string(data, at + u32le(data, at + 8)? as usize, at + size)?);
        }
        at += size;
    }
    let loader = library.parent().ok_or_else(invalid)?;
    let exe = executable.parent().ok_or_else(invalid)?;
    let expand = |path: &str| {
        path.replace("@loader_path", &loader.to_string_lossy())
            .replace("@executable_path", &exe.to_string_lossy())
    };
    let search: Vec<PathBuf> = rpaths
        .iter()
        .map(|path| PathBuf::from(expand(path)))
        .chain([loader.to_path_buf(), exe.to_path_buf(), exe.join("../lib")])
        .collect();
    let search: std::sync::Arc<[PathBuf]> = search.into();
    names
        .into_iter()
        .map(|(name, optional)| {
            let name = if let Some(name) = name.strip_prefix("@rpath/") {
                name.to_owned()
            } else {
                expand(&name)
            };
            if name.contains('@') {
                return Err(invalid());
            }
            Ok(Import {
                name,
                search: search.clone(),
                inherited_rpath: std::sync::Arc::from([]),
                optional,
            })
        })
        .collect()
}
