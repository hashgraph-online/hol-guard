//! Kernel connection identity only; not a user/workflow grant or custody proof.
#![forbid(unsafe_code)]

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn read_linux_credentials(
    stream: &std::os::unix::net::UnixStream,
) -> Result<nix::sys::socket::UnixCredentials, String> {
    nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map_err(|_| "native_peer_identity_unavailable".to_owned())
}

pub(crate) struct UnixPeerIdentity {
    uid: u32,
    gid: u32,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl UnixPeerIdentity {
    pub(crate) fn read(stream: &std::os::unix::net::UnixStream) -> Result<Self, String> {
        stream
            .peer_addr()
            .map_err(|_| "native_peer_identity_unavailable".to_owned())?;
        #[cfg(target_os = "linux")]
        let (uid, gid) = {
            let credentials = read_linux_credentials(stream)?;
            if credentials.pid() <= 0 {
                return Err("native_peer_identity_unavailable".into());
            }
            (credentials.uid(), credentials.gid())
        };
        #[cfg(target_os = "macos")]
        let (uid, gid) = {
            let (uid, gid) = nix::unistd::getpeereid(stream)
                .map_err(|_| "native_peer_identity_unavailable".to_owned())?;
            (uid.as_raw(), gid.as_raw())
        };
        // Reject credentials whose IDs cannot be represented. Linux also
        // requires a connected socket and positive kernel peer PID above.
        if uid == u32::MAX || gid == u32::MAX {
            return Err("native_peer_identity_unavailable".into());
        }
        Ok(Self { uid, gid })
    }

    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }

    pub(crate) fn gid(&self) -> u32 {
        self.gid
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn connected_socket_identity_comes_from_kernel() {
        let (left, right) = UnixStream::pair().unwrap();
        for stream in [&left, &right] {
            let peer = UnixPeerIdentity::read(stream).unwrap();
            assert_eq!(peer.uid(), nix::unistd::geteuid().as_raw());
            assert_eq!(peer.gid(), nix::unistd::getegid().as_raw());
        }
    }

    #[test]
    fn unconnected_socket_cannot_establish_identity() {
        use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
        let socket = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        let stream = UnixStream::from(socket);
        assert_eq!(
            UnixPeerIdentity::read(&stream).err().unwrap(),
            "native_peer_identity_unavailable"
        );
    }
}
