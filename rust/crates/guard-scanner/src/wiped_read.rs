//! Read a stream whole without leaving partial copies in freed memory.
//!
//! Every reader in this crate pulls in plaintext: a file's contents, a git
//! blob, an archive member on its way out of a decoder. `read_to_end` grows
//! its buffer by reallocating, and each growth frees an allocation that still
//! holds everything read so far, so a crash dump taken mid-scan carries about
//! `log2(size)` partial copies of whatever was being read. Reading into fixed
//! chunks never reallocates a filled buffer, each chunk wipes itself when it
//! drops, and the result is allocated once at the size the chunks add up to.

use std::io::{self, Read};

use zeroize::Zeroizing;

/// Chunk size: large enough that a multi-megabyte member costs few reads,
/// small enough that a short stream does not reserve much more than it needs.
const CHUNK_BYTES: usize = 64 * 1024;

/// Read `reader` to its end, keeping no partial copies.
///
/// The bytes read so far are returned alongside the failure rather than
/// instead of it, because a decoder that stops partway through a file has
/// still produced archive, and a credential inside it is still a credential.
/// Callers that want the stricter contract map `Some(error)` to their own.
pub(crate) fn read_whole<R: Read + ?Sized>(
    reader: &mut R,
) -> (Zeroizing<Vec<u8>>, Option<io::Error>) {
    let mut chunks: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    let mut last_used = 0usize;
    let mut failure = None;
    loop {
        let mut chunk = Zeroizing::new(vec![0u8; CHUNK_BYTES]);
        let mut used = 0usize;
        let mut ended = false;
        while used < CHUNK_BYTES {
            match reader.read(&mut chunk[used..]) {
                Ok(0) => {
                    ended = true;
                    break;
                }
                Ok(read) => used += read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    failure = Some(error);
                    ended = true;
                    break;
                }
            }
        }
        if used > 0 {
            chunks.push(chunk);
            last_used = used;
        }
        if ended {
            break;
        }
    }
    let total = chunks.len().saturating_sub(1) * CHUNK_BYTES + last_used;
    let mut whole = Vec::with_capacity(total);
    for (index, chunk) in chunks.iter().enumerate() {
        let used = if index + 1 == chunks.len() {
            last_used
        } else {
            CHUNK_BYTES
        };
        whole.extend_from_slice(&chunk[..used]);
    }
    (Zeroizing::new(whole), failure)
}

/// Read `reader` to its end, treating a failure as no read at all.
pub(crate) fn read_whole_or_fail<R: Read + ?Sized>(
    reader: &mut R,
) -> io::Result<Zeroizing<Vec<u8>>> {
    match read_whole(reader) {
        (whole, None) => Ok(whole),
        (_, Some(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stream_longer_than_one_chunk_is_read_whole() {
        let source: Vec<u8> = (0..200_000usize).map(|index| (index % 251) as u8).collect();
        let mut cursor = io::Cursor::new(source.clone());
        let whole = read_whole_or_fail(&mut cursor).unwrap();
        assert_eq!(*whole, source);
        assert_eq!(whole.capacity(), source.len());
    }

    #[test]
    fn an_empty_stream_reads_as_no_bytes() {
        let mut cursor = io::Cursor::new(Vec::new());
        assert!(read_whole_or_fail(&mut cursor).unwrap().is_empty());
    }

    /// A signal handler installed without `SA_RESTART` interrupts a blocked
    /// read; `read_to_end` retried that, so the chunked reader must too.
    #[test]
    fn an_interrupted_read_is_retried_rather_than_failing_the_call() {
        struct InterruptsOnce {
            interrupted: bool,
            left: usize,
        }
        impl Read for InterruptsOnce {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                let wrote = buffer.len().min(self.left);
                buffer[..wrote].fill(b'x');
                self.left -= wrote;
                Ok(wrote)
            }
        }
        let mut pipe = InterruptsOnce {
            interrupted: false,
            left: 7,
        };
        let whole = read_whole_or_fail(&mut pipe).unwrap();
        assert_eq!(*whole, vec![b'x'; 7]);
    }

    #[test]
    fn a_stream_that_fails_partway_keeps_what_it_produced() {
        struct FailsAfter {
            left: usize,
        }
        impl Read for FailsAfter {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.left == 0 {
                    return Err(io::Error::other("stream ended badly"));
                }
                let wrote = buffer.len().min(self.left);
                buffer[..wrote].fill(b'x');
                self.left -= wrote;
                Ok(wrote)
            }
        }
        let (whole, failure) = read_whole(&mut FailsAfter { left: 100 });
        assert_eq!(whole.len(), 100);
        assert!(failure.is_some());
        assert!(read_whole_or_fail(&mut FailsAfter { left: 100 }).is_err());
    }
}
