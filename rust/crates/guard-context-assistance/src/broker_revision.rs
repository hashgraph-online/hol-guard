use super::*;

impl BrokerRevision {
    pub(super) fn validate(&self) -> Result<(), RuntimeError> {
        if !digest(&self.epoch)
            || self.version.is_empty()
            || self.version.len() > 20
            || (self.version.len() > 1 && self.version.starts_with('0'))
            || !self.version.bytes().all(|b| b.is_ascii_digit())
            || self.version.parse::<u64>().is_err()
        {
            return Err(RuntimeError::TransportFailed);
        }
        Ok(())
    }
}
