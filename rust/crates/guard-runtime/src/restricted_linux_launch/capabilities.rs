//! Drop every capability, including kernel additions unknown to the library.
use super::plan::Result;
use std::io::Read;

pub(super) fn drop_all() -> Result<()> {
    nix::sys::prctl::set_no_new_privs()
        .map_err(|_| "Linux privilege escalation could not be disabled.")?;
    capctl::caps::ambient::clear().map_err(|_| "Linux ambient capability drop failed.")?;
    capctl::caps::bounding::clear().map_err(|_| "Linux bounding capability drop failed.")?;
    capctl::caps::CapState::empty()
        .set_current()
        .map_err(|_| "Linux active capability drop failed.")?;
    let mut bytes = Vec::new();
    std::fs::File::open("/proc/self/status")
        .map_err(|_| "Linux capability verification failed.")?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "Linux capability verification failed.")?;
    if bytes.len() > 65536 {
        return Err("Linux capability verification failed.");
    }
    // Kernel hexadecimal fields include unknown capability bits as well.
    for prefix in [
        b"CapInh:".as_slice(),
        b"CapPrm:",
        b"CapEff:",
        b"CapBnd:",
        b"CapAmb:",
    ] {
        let value = bytes
            .split(|v| *v == b'\n')
            .find_map(|line| line.strip_prefix(prefix))
            .and_then(|v| std::str::from_utf8(v).ok())
            .ok_or("Linux capability verification failed.")?
            .trim();
        if value.is_empty() || !value.bytes().all(|v| v == b'0') {
            return Err("Linux active capabilities remain.");
        }
    }
    if !nix::sys::prctl::get_no_new_privs()
        .map_err(|_| "Linux privilege boundary did not persist.")?
    {
        return Err("Linux privilege boundary did not persist.");
    }
    Ok(())
}
