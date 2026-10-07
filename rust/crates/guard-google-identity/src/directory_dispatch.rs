use super::PreparedGoogleBusinessRequest;
use crate::dispatch::{GoogleDispatchError, GoogleSendAttempt, RawSendAttempt};
use guard_command::business_input::PreparedBusinessInputV1;

impl PreparedGoogleBusinessRequest {
    /// Transport only for the registered native worker. It must obtain `owned`
    /// through the native single-use claim, enforce current floors/budgets and
    /// journal the attempt before calling. This method does not grant permission.
    /// No route is enabled by this API. It consumes the held credential/input.
    pub fn dispatch_owned(
        self,
        owned: PreparedBusinessInputV1,
    ) -> Result<GoogleSendAttempt, GoogleDispatchError> {
        self.dispatch_with(owned, |input, bytes| input.send_once(bytes))
    }
    fn dispatch_with(
        self,
        owned: PreparedBusinessInputV1,
        send: impl FnOnce(
            crate::worker_input::GoogleWorkerInput,
            &[u8],
        ) -> Result<RawSendAttempt, GoogleDispatchError>,
    ) -> Result<GoogleSendAttempt, GoogleDispatchError> {
        if self.prepared.binding() != owned.binding()
            || self.prepared.primary_bytes() != owned.primary_bytes()
            || owned.attachments().next().is_some()
        {
            return Err(GoogleDispatchError::InputChanged);
        }
        if !self.is_current() {
            return Err(GoogleDispatchError::Expired);
        }
        let account = self
            .prepared
            .facts()
            .provider
            .account_binding
            .as_deref()
            .ok_or(GoogleDispatchError::InputChanged)?;
        let namespace = &self.resolved.directory.namespace_key;
        let input = self.resolved.input.into_input();
        match send(input, owned.primary_bytes())? {
            RawSendAttempt::Accepted(ack) => Ok(GoogleSendAttempt::ApiAccepted {
                message_binding: crate::binding(
                    namespace,
                    b"hol-guard.google-send-acknowledgement.v1\0",
                    &[account, ack.id.as_str(), ack.thread_id.as_str()],
                ),
            }),
            RawSendAttempt::Unconfirmed => Ok(GoogleSendAttempt::Unconfirmed),
        }
    }
}

#[cfg(test)]
#[path = "directory_dispatch_tests.rs"]
mod tests;
