//! Bounded transient input for explicit batched preparation, never hook state.
use super::{io, Session};

impl Session {
    /// Retain at most 64 already verified objects (4 MiB). Completed job roots
    /// are removed by drive. Only an overflow object is spilled to the existing
    /// transport CAS; large concatenations can still progress at fixed memory.
    /// Small records never need a temporary per-object filesystem publication.
    pub(super) fn buffer_fetched(&mut self, data: Vec<u8>) -> io::Result<()> {
        let digest = io::hash(&data);
        if self.fetched.len() == 64 && !self.fetched.contains_key(&digest) {
            let (_, evicted) = self
                .fetched
                .pop_first()
                .ok_or("catalog_prepare_session_invalid")?;
            io::put(
                &self.directory("transport"),
                &evicted,
                "data",
                evicted.len(),
            )?;
        }
        self.fetched.insert(digest, data);
        Ok(())
    }
}
