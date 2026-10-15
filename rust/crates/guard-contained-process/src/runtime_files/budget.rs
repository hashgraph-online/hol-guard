use super::*;

pub(super) fn check_window(deadline: Instant, cancel: &AtomicBool) -> io::Result<()> {
    if Instant::now() >= deadline || cancel.load(Ordering::Acquire) {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "runtime dependency deadline",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn extend_pending(
    pending: &mut VecDeque<Import>,
    edges: &mut usize,
    imports: Vec<Import>,
) -> io::Result<()> {
    *edges = edges.checked_add(imports.len()).ok_or_else(invalid)?;
    if *edges > 65_536 || pending.len().saturating_add(imports.len()) > 4096 {
        return Err(invalid());
    }
    pending.extend(imports);
    Ok(())
}
